# Description
**CVE-2020-11738**
Duplicator 1.3.24 & 1.3.26 - Unauthenticated Arbitrary File Download. According to the vendor, the vulnerability was only in two versions v1.3.24 and v1.3.26, the vulnerability wasn't present in versions 1.3.22 and before.

# Usage:
```bash
Usage:
    python3 CVE-2020-11738.py <domain> <file>

Example:
    python3 CVE-2020-11738.py http:/pwnme.me/wordpress /etc/passwd
```
# POC
![](./CVE-2020-11738.gif)