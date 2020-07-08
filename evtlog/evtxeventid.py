# a script to help construct dictionaries of interesting event IDs from a security viewpoint
# 'Interesting' IDs are taken from open sources referenced here
# Some initial text processing is required

# extracted from
# https://www.exabeam.com/siem-guide/siem-concepts/event-log/
securityevts1 = {4624: 'Successful log on', 4625: 'Failed log on', 4634: 'Account log off', 4648: 'Log on attempt with explicit credentials', 4719: 'System audit policy change', 4964: 'Special group assigned to new log on attempt', 1102: 'Audit log cleared', 4720: 'New user account created', 4722: 'User account enabled', 4723: 'Attempt to change password', 4725: 'User account disabled', 4728: 'User added to privileged global group', 4732: 'User added to privileged local group', 4756: 'User was added to privileged universal group', 4738: 'Change to user account', 4740: 'User locked out of an account', 4767: 'User account unlocked', 4735: 'Change to privileged local group', 4737: 'Change to privileged global group', 4755: 'Change to universal group', 4772: 'Failed request for Kerberos ticket', 4777: 'Domain controller failed to validate credentials', 4782: 'Account password hash accessed', 4616: 'System time changed', 4657: 'Change to registry value', 4697: 'Service install attempt', 4946: 'Rule added to Windows Firewall exception', 4947: 'Rule modified in Windows Firewall exception', 4950: 'Windows Firewall settings change', 4954: 'Change to Windows Firewall Group Policy'}
fwevts1 = {5025: 'Windows Firewall service stopped', 5031: 'Application blocked by Windows Firewall from accepting traffic', 5155: 'Windows Filtering Platform blocked a service from listening on a port'}

# extracted from
# https://blog.netwrix.com/2014/12/03/detecting-a-security-threat-in-event-logs
# 4663 omitted as description inconsistent
# 1102 omitted as it is widely covered elsewhere
# descriptions taken from 
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
securityevts2 = {4724: 'An attempt was made to reset an accounts password',  4704: 'A user right was assigned',  4717: 'System security access was granted to an account',  4719: 'System audit policy was changed', 4739: 'Domain Policy was changed'}


# extracted from 
# https://www.xplg.com/windows-server-security-events-list/
# some descriptions taken from
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
securityevts3 = {4624: 'Successful account log on', 4625: 'Failed account log on', 4634: 'An account logged off', 4648: 'A logon attempt was made with explicit credentials', 4719: 'System audit policy was changed.', 4964: 'A special group has been assigned to a new log on', 1102: 'Audit log was cleared. This can relate to a potential attack', 4720: 'A user account was created', 4722: 'A user account was enabled', 4723: 'An attempt was made to change the password of an account', 4725: 'A user account was disabled', 4728: 'A user was added to a privileged global group', 4732: 'A user was added to a privileged local group', 4756: 'A user was added to a privileged universal group', 4738: 'A user account was changed', 4740: 'A user account was locked out', 4767: 'A user account was unlocked', 4735: 'A privileged local group was modified', 4737: 'A privileged global group was modified', 4755: 'A privileged universal group was modified', 4772: 'A Kerberos authentication ticket request failed', 4777: 'The domain controller failed to validate the credentials of an account.', 4782: 'Password hash an account was accessed', 4616: 'System time was changed', 4657: 'A registry value was changed', 4697: 'An attempt was made to install a service', 4698: 'A scheduled task was created', 4699: 'A scheduled task was deleted', 4700: 'A scheduled task was enabled', 4701: 'A scheduled task was disabled', 4702: 'A scheduled task was updated', 4946: 'A rule was added to the Windows Firewall exception list', 4947: 'A rule was modified in the Windows Firewall exception list', 4950: 'A setting was changed in Windows Firewall', 4954: 'Group Policy settings for Windows Firewall has changed'}
fwevts2 = {5025: 'The Windows Firewall service has been stopped', 5031: 'Windows Firewall blocked an application from accepting incoming traffic', 5152: 'The Windows Filtering Platform blocked a packet', 5153: 'A more restrictive Windows Filtering Platform filter has blocked a packet', 5155: 'Windows Filtering Platform blocked an application or service from listening on a port', 5157: 'Windows Filtering Platform blocked a connection', 5447: 'A Windows Filtering Platform filter was changed'}

# Union of security (and fw) sets and find overlapping events

# Finally, print dictionary of event IDs
seen = set()
repeated = set()
for k in securityevts1:
    if (k not in seen) and (k not in repeated):
        seen.add(k)
    elif k in seen:
        repeated.add(k)

for k in securityevts2:
    if (k not in seen) and (k not in repeated):
        seen.add(k)
    elif k in seen:
        repeated.add(k)

for k in securityevts3:
    if (k not in seen) and (k not in repeated):
        seen.add(k)
    elif k in seen:
        repeated.add(k)

print("Repeated IDs for security events")
print(repeated)

print("Unique IDs")
print("securityevts1")
for k in securityevts1:
    if k not in repeated:
        print(k)

print("securityevts2")
for k in securityevts2:
    if k not in repeated:
        print(k)

print("securityevts3")
for k in securityevts3:
    if k not in repeated:
        print(k)

# Construct set of security events
securityevts = dict()
for k in securityevts1:
    if k not in securityevts:
        securityevts[k] = securityevts1[k]

for k in securityevts2:
    if k not in securityevts:
        securityevts[k] = securityevts2[k]

for k in securityevts3:
    if k not in securityevts:
        securityevts[k] = securityevts3[k]

print(len(securityevts))
print(securityevts)

# Do the same for fwevts
fwevts = dict()
for k in fwevts1:
    if k not in fwevts:
        fwevts[k] = fwevts1[k]
        
for k in fwevts2:
    if k not in fwevts:
        fwevts[k] = fwevts2[k]
        
print(len(fwevts))
print(fwevts)

# Event ID output - consolidated list to use for filters, for a start
# {4624: 'Successful log on', 4625: 'Failed log on', 4634: 'Account log off', 4648: 'Log on attempt with explicit credentials', 4719: 'System audit policy change', 4964: 'Special group assigned to new log on attempt', 1102: 'Audit log cleared', 4720: 'New user account created', 4722: 'User account enabled', 4723: 'Attempt to change password', 4725: 'User account disabled', 4728: 'User added to privileged global group', 4732: 'User added to privileged local group', 4756: 'User was added to privileged universal group', 4738: 'Change to user account', 4740: 'User locked out of an account', 4767: 'User account unlocked', 4735: 'Change to privileged local group', 4737: 'Change to privileged global group', 4755: 'Change to universal group', 4772: 'Failed request for Kerberos ticket', 4777: 'Domain controller failed to validate credentials', 4782: 'Account password hash accessed', 4616: 'System time changed', 4657: 'Change to registry value', 4697: 'Service install attempt', 4946: 'Rule added to Windows Firewall exception', 4947: 'Rule modified in Windows Firewall exception', 4950: 'Windows Firewall settings change', 4954: 'Change to Windows Firewall Group Policy', 4724: 'An attempt was made to reset an accounts password', 4704: 'A user right was assigned', 4717: 'System security access was granted to an account', 4739: 'Domain Policy was changed', 4698: 'A scheduled task was created', 4699: 'A scheduled task was deleted', 4700: 'A scheduled task was enabled', 4701: 'A scheduled task was disabled', 4702: 'A scheduled task was updated'}
# {5025: 'Windows Firewall service stopped', 5031: 'Application blocked by Windows Firewall from accepting traffic', 5155: 'Windows Filtering Platform blocked a service from listening on a port', 5152: 'The Windows Filtering Platform blocked a packet', 5153: 'A more restrictive Windows Filtering Platform filter has blocked a packet', 5157: 'Windows Filtering Platform blocked a connection', 5447: 'A Windows Filtering Platform filter was changed'}


