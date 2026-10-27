#!/bin/sh
# Reports which of the toolbox packages exist in the current Kali repo.
# Exists so the image build list can be corrected from evidence rather than by
# guessing which name was wrong.
set -u
apt-get update -qq >/dev/null 2>&1 || { echo "apt-get update FAILED"; exit 1; }
for p in ca-certificates curl wget dnsutils whois netcat-traditional netcat-openbsd \
         openssl iputils-ping traceroute nmap masscan ffuf gobuster feroxbuster dirb \
         whatweb nikto nuclei sqlmap hydra seclists wordlists; do
  if apt-cache show "$p" >/dev/null 2>&1; then
    echo "OK   $p"
  else
    echo "MISS $p"
  fi
done
