# CVE-2022-23131 Zabbix - SAML SSO Authentication Bypass  
When SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor because a user login stored in the session was not verified.
# Use
### Exploit
```
python3 CVE-2022-23131.py https://url.zabbix.example admin
```
# Reference
- https://support.zabbix.com/browse/ZBX-20350
- https://blog.sonarsource.com/zabbix-case-study-of-unsafe-session-storage
- https://nvd.nist.gov/vuln/detail/CVE-2022-23131
- https://github.com/1mxml/CVE-2022-23131
