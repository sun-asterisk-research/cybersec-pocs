# CVE-2022-24260 SQL Injection VoipMonitor <= 24.96 
A SQL injection vulnerability in Voipmonitor GUI before v24.96 allows attackers to escalate privileges to the Administrator level (can exploit to RCE)
# Use
### Exploit
```
python3 CVE-2022-24260.py -u http://127.0.0.1
```
# Reference
- https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-24260.yaml
- https://kerbit.io/research/read/blog/3
- https://nvd.nist.gov/vuln/detail/CVE-2022-24260
- https://www.voipmonitor.org/changelog-gui?major=5