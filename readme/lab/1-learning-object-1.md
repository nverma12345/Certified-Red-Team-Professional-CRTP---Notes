---
icon: vial
---

# 1 - Learning Object 1️

## Tasks

1 - Enumerate following for the dollarcorp domain:

* Users
* Computers
* Domain Administrators
* Enterprise Administrators

2 - Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.\
3 - Find a file share where studentx has Write permissions.

Flag 1 \[Student VM] - SID of the member of the Enterprise Admins group 🚩



## Solutions

### 1 - Enumerate following for the dollarcorp domain

Start InviShell and PowerView

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Powerview.ps1
```

#### 1.1. - dollarcorp.moneycorp.local Domain Users

```powershell
Get-DomainUser -Domain dollarcorp.moneycorp.local | select samaccountname
```

```powershell
samaccountname
--------------
Administrator
Guest
krbtgt
sqladmin
websvc
srvadmin
appadmin
svcadmin
testda
mgmtadmin
ciadmin
sql1admin
studentadmin
devopsadmin
student861
student862
student863
student864
student865
student866
student867
student868
student869
student870
student871
student872
student873
student874
student875
student876
student877
student878
student879
student880
Control861user
Control862user
Control863user
Control864user
Control865user
Control866user
Control867user
Control868user
Control869user
Control870user
Control871user
Control872user
Control873user
Control874user
Control875user
Control876user
Control877user
Control878user
Control879user
Control880user
Support861user
Support862user
Support863user
Support864user
Support865user
Support866user
Support867user
Support868user
Support869user
Support870user
Support871user
Support872user
Support873user
Support874user
Support875user
Support876user
Support877user
Support878user
Support879user
Support880user
VPN861user
VPN862user
VPN863user
VPN864user
VPN865user
VPN866user
VPN867user
VPN868user
VPN869user
VPN870user
VPN871user
VPN872user
VPN873user
VPN874user
VPN875user
VPN876user
VPN877user
VPN878user
VPN879user
VPN880user
```

#### 1.2 - dollarcorp.moneycorp.local Domain Computers

```powershell
Get-DomainComputer -Domain dollarcorp.moneycorp.local | Select-Object -ExpandProperty dnshostname
```

```powershell
dcorp-dc.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
dcorp-std861.dollarcorp.moneycorp.local
dcorp-std862.dollarcorp.moneycorp.local
dcorp-std863.dollarcorp.moneycorp.local
dcorp-std864.dollarcorp.moneycorp.local
dcorp-std865.dollarcorp.moneycorp.local
dcorp-std866.dollarcorp.moneycorp.local
dcorp-std867.dollarcorp.moneycorp.local
dcorp-std868.dollarcorp.moneycorp.local
dcorp-std869.dollarcorp.moneycorp.local
dcorp-std870.dollarcorp.moneycorp.local
dcorp-std871.dollarcorp.moneycorp.local
dcorp-std872.dollarcorp.moneycorp.local
dcorp-std873.dollarcorp.moneycorp.local
dcorp-std874.dollarcorp.moneycorp.local
dcorp-std875.dollarcorp.moneycorp.local
dcorp-std876.dollarcorp.moneycorp.local
dcorp-std877.dollarcorp.moneycorp.local
dcorp-std878.dollarcorp.moneycorp.local
dcorp-std879.dollarcorp.moneycorp.local
dcorp-std880.dollarcorp.moneycorp.local
```

#### 1.3 - dollarcorp.moneycorp.local Domain Administrators

```powershell
Get-DomainGroupMember -Domain dollarcorp.moneycorp.local -Identity "Domain Admins" -Recurse
```



```powershell
GroupDomain             : dollarcorp.moneycorp.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberDomain            : dollarcorp.moneycorp.local
MemberName              : svcadmin
MemberDistinguishedName : CN=svc admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-719815819-3726368948-3917688648-1118

GroupDomain             : dollarcorp.moneycorp.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberDomain            : dollarcorp.moneycorp.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-719815819-3726368948-3917688648-500
```

#### 1.4 - dollarcorp.moneycorp.local Domain Enterprise Administrators

```powershell
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain dollarcorp.moneycorp.local
```

No results, we need to check if it's present into a forest, check it:

```powershell
Get-DomainTrust
```

```powershell
SourceName      : dollarcorp.moneycorp.local
TargetName      : moneycorp.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/12/2022 5:59:01 AM
WhenChanged     : 4/19/2025 4:04:35 AM

SourceName      : dollarcorp.moneycorp.local
TargetName      : us.dollarcorp.moneycorp.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/12/2022 6:22:51 AM
WhenChanged     : 4/25/2025 5:08:47 AM

SourceName      : dollarcorp.moneycorp.local
TargetName      : eurocorp.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS
TrustDirection  : Bidirectional
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 4/25/2025 5:03:33 AM
```

Great, now we can update our command adding monycorp.local and retrieve Enterprise Admins:

```powershell
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

```powershell
GroupDomain             : moneycorp.local
GroupName               : Enterprise Admins
GroupDistinguishedName  : CN=Enterprise Admins,CN=Users,DC=moneycorp,DC=local
MemberDomain            : moneycorp.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-335606122-960912869-3279953914-500
```

### 2 - Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain

Using the pre-built search filter we can identify quickly the shortest path to Domain Admin

<figure><img src="../../.gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

### 3 - Find a file share where studentx has Write permissions

First to all enumerate all computer of current domain displaying relative dnshostname and save them in a file

```powershell
Get-DomainComputer | select -ExpandProperty dnshostname | Out-File -FilePath "C:\AD\Tools\servers.txt"
```

```powershell
dcorp-dc.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
dcorp-std861.dollarcorp.moneycorp.local
dcorp-std862.dollarcorp.moneycorp.local
dcorp-std863.dollarcorp.moneycorp.local
dcorp-std864.dollarcorp.moneycorp.local
dcorp-std865.dollarcorp.moneycorp.local
dcorp-std866.dollarcorp.moneycorp.local
dcorp-std867.dollarcorp.moneycorp.local
dcorp-std868.dollarcorp.moneycorp.local
dcorp-std869.dollarcorp.moneycorp.local
dcorp-std870.dollarcorp.moneycorp.local
dcorp-std871.dollarcorp.moneycorp.local
dcorp-std872.dollarcorp.moneycorp.local
dcorp-std873.dollarcorp.moneycorp.local
dcorp-std874.dollarcorp.moneycorp.local
dcorp-std875.dollarcorp.moneycorp.local
dcorp-std876.dollarcorp.moneycorp.local
dcorp-std877.dollarcorp.moneycorp.local
dcorp-std878.dollarcorp.moneycorp.local
dcorp-std879.dollarcorp.moneycorp.local
dcorp-std880.dollarcorp.moneycorp.local
```

Load PowerHuntShares tool importing PowerHuntShares.psm1 module and run HuntSMBShares:

{% hint style="info" %}
Don't run HuntSMBShares after starting PowerView
{% endhint %}

```powershell
Import-Module C:\AD\Tools\PowerHuntShares.psm1
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```

<figure><img src="../../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

Lab Machine hasn't a network connection, so transfer file generated into our local machine using SMB tools folder share and open it via browser.

Checking into ShareGraph the AI share has the write permission for everyone:

<figure><img src="../../.gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
AI
{% endhint %}

### Flag 1 \[Student VM] - SID of the member of the Enterprise Admins group 🚩

```powershell
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

```powershell
GroupDomain             : moneycorp.local
GroupName               : Enterprise Admins
GroupDistinguishedName  : CN=Enterprise Admins,CN=Users,DC=moneycorp,DC=local
MemberDomain            : moneycorp.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-335606122-960912869-3279953914-500
```
