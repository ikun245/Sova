#!/bin/sh
# Reports which toolbox binaries are actually installed in the image, so a
# stale image cannot be mistaken for a working one.
set -u
for t in nmap masscan sqlmap hydra gobuster nikto whatweb dirb dig curl wget nc \
         ffuf feroxbuster nuclei sqlmap; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "OK   $t"
  else
    echo "MISS $t"
  fi
done
echo "--- wordlists ---"
[ -d /usr/share/seclists ] && echo "OK   seclists" || echo "MISS seclists"
[ -d /usr/share/wordlists ] && echo "OK   wordlists" || echo "MISS wordlists"
