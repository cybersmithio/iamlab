FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      samba-ad-dc samba-ad-provision krb5-user bind9-dnsutils ldb-tools smbclient ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 135/tcp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp 3269/tcp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
