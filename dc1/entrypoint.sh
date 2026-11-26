#!/bin/bash
set -euo pipefail
: "${REALM:?}" "${DOMAIN:?}" "${DC_IP:?}" "${DNS_FORWARDER:?}"

# Provision only on first boot (empty volume)
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  : "${ADMIN_PASS:?ADMIN_PASS required for first provision}"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL \
    --realm="$REALM" --domain="$DOMAIN" --adminpass="$ADMIN_PASS" \
    --host-ip="$DC_IP" \
    --option="dns forwarder = ${DNS_FORWARDER}"
fi

# Re-applied every boot (not on persistent volumes)
cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf
printf 'nameserver 127.0.0.1\nsearch %s\n' "${REALM,,}" > /etc/resolv.conf

exec samba --foreground --no-process-group --debug-stdout
