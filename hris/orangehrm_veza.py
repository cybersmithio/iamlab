#!/usr/bin/env python3
"""
OrangeHRM -> Veza OAA connector (Custom HRIS template) with Lifecycle Management write-back

Pulls employees and org subunits from the OrangeHRM 5.x REST API (v2) and
pushes them to Veza as a Custom HRIS provider ("hris" template).

Write-back: Veza LCM cannot authenticate to OrangeHRM itself (OrangeHRM 5.x only
supports OAuth2 Authorization Code + PKCE; Veza REST credentials support client
credentials / password grant only). So `serve` runs a small endpoint that holds the
OrangeHRM refresh token. A Veza LCM "Send REST Payload" action, routed through an
Insight Point, calls it to set an employee's work email in OrangeHRM.

Auth note: run `auth` once interactively to get a refresh token; `sync` and `serve`
then run headless and refresh as needed. The token inherits the consenting user's
role, so consent as an Admin.

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

Write-back setup:
  # 1. One-time: create the Send REST Payload provider/data source (Insight Point ID is
  #    under Integrations > Insight Points in Veza)
  export VEZA_INSIGHT_POINT_ID=<uuid>
  python orangehrm_veza.py setup-writeback

  # 2. Run the endpoint (container on the lab network, token file mounted read-write)
  export WRITEBACK_TOKEN=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')
  python orangehrm_veza.py serve [--cert cert.pem --key key.pem]

  # 3. Test
  curl -X PUT http://localhost:8780/employee-id/0001/work-email \
       -H "Authorization: Bearer $WRITEBACK_TOKEN" -H "Content-Type: application/json" \
       -d '{"email":"test.user@lab.local"}'

  # 4. In Veza: Bearer credential holding WRITEBACK_TOKEN; Send REST Payload action after
  #    the AD Provision Account step: Data Source = write-back data source, PUT,
  #    URL .../employee-id/{employee_number}/work-email,
  #    payload {"email": "{ActiveDirectoryUser.email}"}
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import secrets
import ssl
import sys
import threading
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

    def put(self, path, body):
        """PUT JSON; returns the response (not raised) so callers can pass validation errors back."""
        r = None
        for attempt in range(4):
            r = self.s.put(f"{self.api}{path}", json=body, timeout=60, verify=self.auth.verify,
                           headers={"Authorization": f"Bearer {self.auth.access_token()}",
                                    "Accept": "application/json"})
            if r.status_code == 401 and attempt == 0:
                self.auth.refresh()
                continue
            if r.status_code in (429, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            break
        return r

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
# LCM write-back: provider setup + endpoint called by Veza Send REST Payload
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s{}]+@[^@\s{}]+\.[^@\s{}]+$")  # also rejects unresolved {placeholders}
CONTACT_PUT_FIELDS = ("street1", "street2", "city", "province", "zipCode", "countryCode",
                      "homeTelephone", "workTelephone", "mobile", "workEmail", "otherEmail")
_write_lock = threading.Lock()


def setup_writeback(provider_name, data_source_name, insight_point_id):
    """Create the application-template provider that gives LCM a Data Source routed via the
    Insight Point (external_lifecycle_management_type=SEND_REST_PAYLOAD). Separate from the
    HRIS provider; data_plane_id is set at creation and cannot be changed afterwards."""
    from oaaclient.client import OAAClient
    from oaaclient.templates import CustomApplication

    veza_url = env("VEZA_URL").rstrip("/")
    if not veza_url.startswith(("http://", "https://")):
        veza_url = "https://" + veza_url
    api_key = env("VEZA_API_KEY")
    veza = OAAClient(url=veza_url, token=api_key)

    if veza.get_provider(provider_name):
        log.info("Provider '%s' exists; data_plane_id can't be changed (delete/recreate to move it)",
                 provider_name)
    else:
        r = requests.post(f"{veza_url}/api/v1/providers/custom",
                          headers={"authorization": f"Bearer {api_key}",
                                   "Content-Type": "application/json"},
                          json={"name": provider_name, "custom_template": "application",
                                "provisioning": True,
                                "external_lifecycle_management_type": "SEND_REST_PAYLOAD",
                                "data_plane_id": insight_point_id},
                          timeout=30)
        if r.status_code >= 400:
            sys.exit(f"Creating write-back provider failed ({r.status_code}): {r.text}")
        log.info("Created provider '%s' (SEND_REST_PAYLOAD)", provider_name)

    # The data source only appears in the LCM action's Data Source dropdown once a payload is pushed.
    app = CustomApplication(name=provider_name, application_type="OrangeHRM Write-Back")
    app.add_local_user("orangehrm-writeback")
    veza.push_application(provider_name=provider_name, data_source_name=data_source_name,
                          application_object=app)
    log.info("Data source '%s' ready; select it in the Send REST Payload action", data_source_name)


def contact_put_body(current, work_email):
    """Assumes PUT replaces the whole contact record, so carry existing fields through.
    VERIFY field names against a DevTools capture of the OrangeHRM UI's Contact Details save."""
    body = {k: current.get(k) for k in CONTACT_PUT_FIELDS if k in current}
    country = current.get("country")
    if isinstance(country, dict) and country.get("countryCode"):
        body["countryCode"] = country["countryCode"]
    body["workEmail"] = work_email
    return body


def resolve_emp_number(client, employee_id):
    """HR-visible employee ID -> empNumber. nameOrId is a partial match, so require an exact hit."""
    for e in client.paged("/pim/employees", {"nameOrId": employee_id, "includeEmployees": "onlyCurrent"}):
        if str(e.get("employeeId")) == str(employee_id):
            return e["empNumber"]
    return None


def set_work_email(client, emp_number, email, overwrite=False):
    path = f"/pim/employee/{emp_number}/contact-details"
    with _write_lock:  # also serializes token refreshes
        current = client.get(path).get("data") or {}
        existing = (current.get("workEmail") or "").strip()
        if existing.lower() == email.lower():
            return 200, {"changed": False, "reason": "already_set"}
        if existing and not overwrite:
            log.warning("empNumber %s already has work email %s; keeping it", emp_number, existing)
            return 200, {"changed": False, "reason": "existing_email_kept"}
        r = client.put(path, contact_put_body(current, email))
    if r.status_code >= 400:
        return 502, {"changed": False, "reason": "orangehrm_rejected",
                     "status": r.status_code, "detail": r.text[:500]}
    return 200, {"changed": True}


def make_handler(client, secret):
    route = re.compile(r"^/(emp-number|employee-id)/([^/]+)/work-email$")

    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_PUT(self):
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {secret}".encode()):
                return self._reply(401, {"error": "unauthorized"})
            m = route.match(urllib.parse.urlparse(self.path).path)
            if not m:
                return self._reply(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._reply(400, {"error": "invalid JSON"})
            email = str(body.get("email", "")).strip().lower()
            if not EMAIL_RE.match(email):
                return self._reply(400, {"error": f"invalid email: {email!r}"})
            kind, ref = m.group(1), urllib.parse.unquote(m.group(2))
            try:
                emp = int(ref) if kind == "emp-number" else resolve_emp_number(client, ref)
                if emp is None:
                    return self._reply(404, {"error": f"no current employee with ID {ref}"})
                code, out = set_work_email(client, emp, email, bool(body.get("overwrite")))
            except (requests.RequestException, SystemExit, ValueError) as e:
                log.error("Write-back for %s failed: %s", ref, e)
                return self._reply(502, {"error": str(e)})
            log.info("%s -> %s %s", self.path, code, out)
            self._reply(code, out)

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

    return Handler


def serve(client, host, port, secret, cert=None, key=None):
    srv = http.server.ThreadingHTTPServer((host, port), make_handler(client, secret))
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log.info("Write-back endpoint listening on %s:%d (%s)", host, port, "TLS" if cert else "plain HTTP")
    srv.serve_forever()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="OrangeHRM -> Veza OAA HRIS connector with LCM write-back")
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

    sv = sub.add_parser("serve", help="Run the write-back endpoint that Veza LCM calls")
    sv.add_argument("--host", default=os.getenv("WRITEBACK_HOST", "0.0.0.0"))
    sv.add_argument("--port", type=int, default=int(os.getenv("WRITEBACK_PORT", "8780")))
    sv.add_argument("--cert", help="TLS certificate (PEM)")
    sv.add_argument("--key", help="TLS private key (PEM)")

    sw = sub.add_parser("setup-writeback", help="Create the Veza provider/data source for LCM write-back")
    sw.add_argument("--provider", default="OrangeHRM Write-Back")
    sw.add_argument("--datasource", default="OrangeHRM Write-Back")
    sw.add_argument("--insight-point-id", default=os.getenv("VEZA_INSIGHT_POINT_ID"))

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "setup-writeback":  # needs no OrangeHRM auth
        if not args.insight_point_id:
            sys.exit("Provide --insight-point-id or VEZA_INSIGHT_POINT_ID")
        setup_writeback(args.provider, args.datasource, args.insight_point_id)
        return

    base_url = env("ORANGEHRM_URL").rstrip("/")
    auth = OrangeHRMAuth(base_url, env("ORANGEHRM_CLIENT_ID"), env("ORANGEHRM_REDIRECT_URI"),
                         args.token_file, verify_tls=not args.insecure)

    if args.cmd == "auth":
        auth.interactive_login()
        return

    client = OrangeHRMClient(auth)

    if args.cmd == "serve":
        secret = env("WRITEBACK_TOKEN")
        if len(secret) < 32:
            sys.exit("WRITEBACK_TOKEN must be at least 32 characters "
                     "(python -c 'import secrets;print(secrets.token_urlsafe(32))')")
        serve(client, args.host, args.port, secret, args.cert, args.key)
        return

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
