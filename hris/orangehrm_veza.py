#!/usr/bin/env python3
"""
OrangeHRM -> Veza OAA connector (Custom HRIS template)

Pulls employees and org subunits from the OrangeHRM 5.x REST API (v2) and
pushes them to Veza as a Custom HRIS provider ("hris" template).

Auth note: OrangeHRM 5.x supports only the OAuth2 Authorization Code grant
with PKCE (no client_credentials). Run `auth` once interactively to get a
refresh token; `sync` then runs headless and refreshes as needed.
The token inherits the consenting user's role, so consent as an Admin.

Setup:
  pip install oaaclient requests

  export ORANGEHRM_URL=http://orangehrm.lab.local         # no trailing /web/index.php
  # Admin > Configuration > Register OAuth Client > Add. Enter any Name and the
  # Redirect URI below; OrangeHRM generates the Client ID after you click Save.
  export ORANGEHRM_CLIENT_ID=<generated Client ID, not the Name you typed>
  export ORANGEHRM_REDIRECT_URI=http://localhost:8765/callback  # must match the registered value exactly
  python orangehrm_veza.py auth

  export VEZA_URL=https://<tenant>.vezacloud.com
  export VEZA_API_KEY=<veza api key>
  python orangehrm_veza.py sync --dry-run --save-json payload.json   # inspect first
  python orangehrm_veza.py sync                                      # push
"""

import argparse
import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import sys
import time
import urllib.parse

import requests

log = logging.getLogger("orangehrm-veza")

TOKEN_FILE_DEFAULT = os.path.expanduser("~/.orangehrm_veza_token.json")
PAGE_SIZE = 50  # OrangeHRM API default limit


def env(name, required=True):
    val = os.getenv(name)
    if required and not val:
        sys.exit(f"Missing required environment variable: {name}")
    return val


# --------------------------------------------------------------------------
# OAuth2 Authorization Code + PKCE
# --------------------------------------------------------------------------
class OrangeHRMAuth:
    def __init__(self, base_url, client_id, redirect_uri, token_file, verify_tls=True):
        self.base = base_url.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.token_file = token_file
        self.verify = verify_tls
        self.authorize_url = f"{self.base}/web/index.php/oauth2/authorize"
        self.token_url = f"{self.base}/web/index.php/oauth2/token"
        self._tok = None

    def _save(self, tok):
        tok["obtained_at"] = int(time.time())
        fd = os.open(self.token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(tok, f)
        self._tok = tok

    def _load(self):
        if self._tok:
            return self._tok
        if not os.path.exists(self.token_file):
            sys.exit(f"No token file at {self.token_file}. Run the 'auth' command first.")
        with open(self.token_file) as f:
            self._tok = json.load(f)
        return self._tok

    def interactive_login(self):
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(16)
        url = self.authorize_url + "?" + urllib.parse.urlencode({
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
            "state": state,
        })

        redirect = urllib.parse.urlparse(self.redirect_uri)
        result = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != redirect.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                q = urllib.parse.parse_qs(parsed.query)
                result.update({k: v[0] for k, v in q.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OrangeHRM authorization received. You can close this tab.")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer((redirect.hostname, redirect.port or 80), Handler)
        print("Open this URL, log in as an OrangeHRM Admin, and click 'Allow Access':\n")
        print(url + "\n")
        while not result:
            server.handle_request()
        server.server_close()

        if result.get("state") != state:
            sys.exit("OAuth state mismatch, aborting.")
        if "code" not in result:
            sys.exit(f"No authorization code returned: {result}")

        r = requests.post(self.token_url, data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": result["code"],
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
        }, verify=self.verify, timeout=30)
        r.raise_for_status()
        self._save(r.json())
        print(f"Tokens saved to {self.token_file} (mode 600)")

    def refresh(self):
        tok = self._load()
        r = requests.post(self.token_url, data={
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": tok["refresh_token"],
        }, verify=self.verify, timeout=30)
        if r.status_code >= 400:
            sys.exit(f"Token refresh failed ({r.status_code}): {r.text}. Re-run 'auth'.")
        new = r.json()
        new.setdefault("refresh_token", tok["refresh_token"])  # keep old one if not rotated
        self._save(new)

    def access_token(self):
        tok = self._load()
        age = time.time() - tok.get("obtained_at", 0)
        if age > int(tok.get("expires_in", 1800)) - 60:
            log.debug("Access token expired or near expiry, refreshing")
            self.refresh()
        return self._tok["access_token"]


# --------------------------------------------------------------------------
# OrangeHRM API v2 client
# --------------------------------------------------------------------------
class OrangeHRMClient:
    def __init__(self, auth):
        self.auth = auth
        self.api = f"{auth.base}/web/index.php/api/v2"
        self.s = requests.Session()

    def get(self, path, params=None):
        r = None
        for attempt in range(4):
            r = self.s.get(f"{self.api}{path}", params=params, timeout=60, verify=self.auth.verify,
                           headers={"Authorization": f"Bearer {self.auth.access_token()}",
                                    "Accept": "application/json"})
            if r.status_code == 401 and attempt == 0:
                self.auth.refresh()
                continue
            if r.status_code in (429, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            break
        r.raise_for_status()
        return r.json()

    def safe_get(self, path, params=None):
        try:
            return self.get(path, params).get("data") or {}
        except requests.HTTPError as e:
            log.warning("GET %s failed: %s", path, e)
            return {}

    def paged(self, path, params=None):
        params = dict(params or {})
        offset = 0
        while True:
            params.update(limit=PAGE_SIZE, offset=offset)
            body = self.get(path, params)
            data = body.get("data") or []
            yield from data
            offset += len(data)
            total = (body.get("meta") or {}).get("total")
            if not data or (total is not None and offset >= int(total)):
                break


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
def fetch_employees(client, include_past, details):
    params = {"includeEmployees": "currentAndPast" if include_past else "onlyCurrent",
              "model": "detailed"}
    emps = list(client.paged("/pim/employees", params))
    log.info("Fetched %d employees", len(emps))
    if details:
        for i, e in enumerate(emps, 1):
            n = e["empNumber"]
            # Paths and response shapes confirmed against OrangeHRM 5 in the lab.
            # Note: contact-details uses singular /pim/employee/, the rest use /pim/employees/.
            e["_contact"] = client.safe_get(f"/pim/employee/{n}/contact-details")
            e["_job"] = client.safe_get(f"/pim/employees/{n}/job-details")
            e["_contract"] = client.safe_get(f"/pim/employees/{n}/employment-contract")
            if len(e.get("supervisors") or []) > 1:
                # List call doesn't say Direct vs Indirect; /supervisors does.
                try:
                    rows = list(client.paged(f"/pim/employees/{n}/supervisors"))
                    direct = next((r for r in rows
                                   if (r.get("reportingMethod") or {}).get("name") == "Direct"), None)
                    if direct:
                        e["_direct_supervisor"] = (direct.get("supervisor") or {}).get("empNumber")
                except requests.HTTPError as err:
                    log.warning("GET supervisors for %s failed: %s", n, err)
            if i % 25 == 0:
                log.info("  details fetched for %d/%d", i, len(emps))
    return emps


def fetch_subunits(client):
    """Return a flat list of {id, name, parent_id} from /admin/subunits?mode=tree."""
    try:
        tree = client.get("/admin/subunits", {"mode": "tree"}).get("data") or []
    except requests.HTTPError as e:
        log.warning("Could not read subunits (%s); deriving departments from employees only", e)
        return []
    flat = []

    def walk(nodes, parent_id):
        for node in nodes:
            flat.append({"id": node["id"], "name": node.get("name"), "parent_id": parent_id})
            walk(node.get("children") or [], node["id"])

    walk(tree, None)
    log.info("Fetched %d subunits", len(flat))
    return flat


# --------------------------------------------------------------------------
# Transform to Veza HRIS payload
# --------------------------------------------------------------------------
def to_ts(date_str):
    """OrangeHRM 'YYYY-MM-DD' -> RFC3339 timestamp."""
    return f"{date_str[:10]}T00:00:00Z" if date_str else None


def _name(*objs, key):
    """First non-null value of `key` across OrangeHRM reference objects (they return nulls when unset)."""
    for o in objs:
        if isinstance(o, dict) and o.get(key):
            return o[key]
    return None


def map_employment_type(status_name):
    s = (status_name or "").lower()
    for key, val in (("part", "PART_TIME"), ("intern", "INTERN"), ("freelanc", "FREELANCE"),
                     ("contract", "CONTRACTOR"), ("full", "FULL_TIME")):
        if key in s:
            return val
    return None


def build_payload(emps, subunits, base_url, system_name, idp_types):
    groups = {str(su["id"]): {"id": str(su["id"]), "name": su.get("name") or str(su["id"]),
                              "group_type": "DEPARTMENT"} for su in subunits}
    for su in subunits:
        pid = su.get("parent_id")
        if pid is not None and str(pid) in groups:
            groups[str(su["id"])]["parent"] = {"id": str(pid)}

    emp_ids = {str(e["empNumber"]) for e in emps}
    emp_numbers, seen_numbers = {}, set()
    for e in emps:
        n = str(e["empNumber"])
        num = str(e.get("employeeId") or n)
        if num in seen_numbers:
            log.warning("Duplicate employee_number %s (empNumber %s); using empNumber", num, n)
            num = n
        seen_numbers.add(num)
        emp_numbers[n] = num
    seen_emails, employees = set(), []

    for e in emps:
        n = str(e["empNumber"])
        contact, job, contract = e.get("_contact") or {}, e.get("_job") or {}, e.get("_contract") or {}
        first, last = e.get("firstName") or "", e.get("lastName") or ""
        term_rec = job.get("employeeTerminationRecord") or {}
        emp_status = _name(job.get("empStatus"), e.get("empStatus"), key="name")
        terminated = bool(e.get("terminationId") or term_rec.get("id")
                          or (emp_status or "").strip().lower() == "terminated")
        job_title = _name(job.get("jobTitle"), e.get("jobTitle"), key="title")
        job_category = _name(job.get("jobCategory"), key="name")
        location = _name(job.get("location"), key="name")
        subunit = next((s for s in (job.get("subunit"), e.get("subunit"))
                        if isinstance(s, dict) and s.get("id") is not None), {})

        emp_number = emp_numbers[n]

        rec = {
            "id": n,
            "name": f"{first} {last}".strip() or n,
            "employee_number": emp_number,
            "first_name": first,
            "last_name": last,
            "display_full_name": f"{first} {last}".strip(),
            "canonical_name": f"{last}, {first}".strip(", "),
            "is_active": not terminated,
            "employment_status": "INACTIVE" if terminated else "ACTIVE",
            "custom_properties": {"orangehrm_emp_number": n},
        }
        cp = rec["custom_properties"]
        if emp_status:
            cp["orangehrm_employment_status"] = emp_status
        if job_category:
            cp["orangehrm_job_category"] = job_category
        if contract.get("startDate"):
            cp["contract_start_date"] = contract["startDate"][:10]
        if contract.get("endDate"):
            cp["contract_end_date"] = contract["endDate"][:10]

        email = (contact.get("workEmail") or "").strip().lower()
        if email:
            if email in seen_emails:
                log.warning("Duplicate work email %s on empNumber %s; omitted", email, n)
            else:
                rec["email"] = email
                seen_emails.add(email)
        if contact.get("otherEmail"):
            rec["personal_email"] = contact["otherEmail"].strip().lower()
        if job_title:
            rec["job_title"] = job_title
        if location:
            rec["work_location"] = location
        start = job.get("joinedDate") or contract.get("startDate")
        if start:
            rec["start_date"] = to_ts(start)
        if term_rec.get("date"):
            rec["termination_date"] = to_ts(term_rec["date"])
        etype = map_employment_type(emp_status)
        if etype:
            rec["employment_types"] = [etype]

        if subunit:
            sid = str(subunit["id"])
            groups.setdefault(sid, {"id": sid, "name": subunit.get("name") or sid,
                                    "group_type": "DEPARTMENT"})
            rec["department"] = {"id": sid}
            rec["groups"] = [{"id": sid}]

        managers = []
        # Supervisors come from the list call (model=detailed): [{empNumber, firstName, ...}]
        for sup in e.get("supervisors") or []:
            sid = str(sup.get("empNumber", ""))
            if sid in emp_ids:
                managers.append({"id": sid})
            elif sid:
                log.warning("Supervisor %s of %s not in payload (excluded by --current-only?)", sid, n)
        if managers:
            rec["managers"] = managers
            mgr = str(e.get("_direct_supervisor") or managers[0]["id"])
            if mgr in emp_numbers:
                rec["custom_properties"]["orangehrm_mgr_emp_number"] = emp_numbers[mgr]

        if not rec.get("email"):
            log.warning("empNumber %s has no work email; Veza will fall back to employee_number "
                        "for IdP correlation", n)
        employees.append(rec)

    system = {"id": base_url, "name": system_name, "url": base_url}
    if idp_types:
        system["idp_providers"] = idp_types

    return {
        "name": system_name,
        "hris_type": "OrangeHRM",
        "custom_property_definition": {
            "system_properties": {},
            "employee_properties": {"orangehrm_emp_number": "STRING",
                                    "orangehrm_employment_status": "STRING",
                                    "orangehrm_job_category": "STRING",
                                    "contract_start_date": "STRING",
                                    "contract_end_date": "STRING",
                                    "orangehrm_mgr_emp_number": "STRING"},
            "group_properties": {},
        },
        "system": system,
        "employees": employees,
        "groups": list(groups.values()),
    }


# --------------------------------------------------------------------------
# Push to Veza
# --------------------------------------------------------------------------
def create_hris_provider(veza_url, api_key, provider_name, provisioning):
    """POST /api/v1/providers/custom with custom_template=hris and the provisioning flag.
    Called directly so the provisioning flag is sent exactly as Veza's REST API documents it."""
    r = requests.post(f"{veza_url}/api/v1/providers/custom",
                      headers={"authorization": f"Bearer {api_key}",
                               "Content-Type": "application/json"},
                      json={"name": provider_name, "custom_template": "hris",
                            "provisioning": provisioning},
                      timeout=30)
    if r.status_code >= 400:
        sys.exit(f"Creating Veza provider failed ({r.status_code}): {r.text}")
    log.info("Created Veza provider '%s' (hris, provisioning=%s)", provider_name, provisioning)
    return r.json()


def push_to_veza(payload, provider_name, data_source_name, provisioning=True):
    from oaaclient.client import OAAClient, OAAClientError

    veza_url = env("VEZA_URL").rstrip("/")
    if not veza_url.startswith(("http://", "https://")):
        veza_url = "https://" + veza_url
    api_key = env("VEZA_API_KEY")
    veza = OAAClient(url=veza_url, token=api_key)

    existing = veza.get_provider(provider_name)
    if not existing:
        create_hris_provider(veza_url, api_key, provider_name, provisioning)
    elif provisioning and isinstance(existing, dict) and existing.get("provisioning") is False:
        log.warning("Provider '%s' already exists without provisioning enabled. Delete it in Veza "
                    "and re-run to recreate it with provisioning=true.", provider_name)
    try:
        resp = veza.push_metadata(provider_name=provider_name,
                                  data_source_name=data_source_name,
                                  metadata=payload)
        for w in (resp or {}).get("warnings") or []:
            log.warning("Veza: %s", w.get("message", w) if isinstance(w, dict) else w)
        log.info("Pushed %d employees / %d groups to Veza data source '%s'",
                 len(payload["employees"]), len(payload["groups"]), data_source_name)
    except OAAClientError as e:
        log.error("Veza push failed: %s: %s (%s)", e.error, e.message, e.status_code)
        for d in getattr(e, "details", []) or []:
            log.error("  %s", d)
        sys.exit(1)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="OrangeHRM -> Veza OAA HRIS connector")
    ap.add_argument("--token-file", default=os.getenv("ORANGEHRM_TOKEN_FILE", TOKEN_FILE_DEFAULT))
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification to OrangeHRM (lab only)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("auth", help="One-time interactive OAuth2 PKCE login")

    sp = sub.add_parser("sync", help="Extract from OrangeHRM and push to Veza")
    sp.add_argument("--provider", default="OrangeHRM", help="Veza OAA provider name")
    sp.add_argument("--datasource", help="Veza data source name (default: OrangeHRM <host>)")
    sp.add_argument("--system-name", default="OrangeHRM")
    sp.add_argument("--current-only", action="store_true",
                    help="Exclude terminated employees (default includes them so Veza can flag "
                         "leavers who still hold access)")
    sp.add_argument("--no-details", action="store_true",
                    help="Skip per-employee contact/job/contract calls")
    sp.add_argument("--idp-type", action="append", default=[],
                    help="Veza IdP type to link employees to (repeatable), e.g. okta, azure_ad")
    sp.add_argument("--no-provisioning", action="store_true",
                    help="Create the provider without provisioning (not a Lifecycle Management source)")
    sp.add_argument("--save-json", help="Write the OAA payload to this file")
    sp.add_argument("--dry-run", action="store_true", help="Build payload but do not push")

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    base_url = env("ORANGEHRM_URL").rstrip("/")
    auth = OrangeHRMAuth(base_url, env("ORANGEHRM_CLIENT_ID"), env("ORANGEHRM_REDIRECT_URI"),
                         args.token_file, verify_tls=not args.insecure)

    if args.cmd == "auth":
        auth.interactive_login()
        return

    client = OrangeHRMClient(auth)
    emps = fetch_employees(client, include_past=not args.current_only, details=not args.no_details)
    subunits = fetch_subunits(client)
    payload = build_payload(emps, subunits, base_url, args.system_name, args.idp_type)

    if args.save_json:
        with open(args.save_json, "w") as f:
            json.dump(payload, f, indent=2)
        log.info("Payload written to %s", args.save_json)
    if args.dry_run:
        log.info("Dry run: %d employees, %d groups built; not pushed",
                 len(payload["employees"]), len(payload["groups"]))
        return

    ds = args.datasource or f"OrangeHRM {urllib.parse.urlparse(base_url).hostname}"
    push_to_veza(payload, args.provider, ds, provisioning=not args.no_provisioning)


if __name__ == "__main__":
    main()
