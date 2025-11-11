# Hacking Web (client-side) y Post-Explotación

## Agenda y Objetivos de Aprendizaje

Contenido de la sesión
1. Diferenciación entre Ataques Server-Side vs Client Side.
2. Explotación de XSS Almacenado (Stored XSS).
3. Técnica de Secuestro de sesiones (Session Hijacking).
4. Post-Explotación: Cracking de Hashes.
5. Consideraciones éticas y próximos pasos.

Objetivos técnicos
Al finalizar esta clase, serás capaz de: 
* Robar cookies de sesión mediante Javascript inyectado.
* Tomar control de cuentas de usuario sin conocer contraseñas.
* Descifrar contraseñas a partir de hashes del sistema (/etc/shadow).
* Comprender la diferencia crítica entre vectores de ataque dellado del servidor y del cliente.


## Server-side vs Client-side: Paradigmas de ataque

Server-side (Clase 3)
Target: El servidor web
* Inyectamos código que el servidor interpreta (bash, SQ)
* El payload se ejecuta en la infraestructura del servidor
* Ejemplos: Command Injection, SQL Injection
* Compromiso directo del sistema backend

Client-side (clase 4)
Target: el navegador del usuario
* Inyectamos código 

## XSS (Cross-Site Scripting): Fundamentos
Definición técnica
Cross-Site Scripting (XSS) es una vulnerabilidad de seguridad que permite a un atacante inyectar scripts maliciosos en páginas web visualizadas por otros usuarios. Ocurre cuando una aplicación web recibe datos no confiables del usuario y los incluye en su salida HTML sin validación o codificación adecuada.

¿Por qué es peligroso?
El navegador de la víctima no puede distinguir entre el JavaScript legítimo del sitio y nuestro código inyectado. Todo se ejecuta con los mismos privilegios y en el mismo contexto de seguridad. Esto permite al atacante:

Tipos de XSS:
1. Reflected XSS: el payload viaja en la URL. Se ejecuta inmediatamente pero no persiste.
2. Stored XSS: el payload se almacena en la BD. ¡El más peligroso!. Ataca a todos los visitantes.
3. DOM-based XSS: la vulnerabilidad existe en el código JavaScript del lado del cliente.

NOTA: hoy nos enfocaremos en Stored XSS, ya que representa el mayor riesgo para aplicaciones web reales. Un sólo payload puede comprometer a cientos o miles de usuarios sin intervención adicional del atacante.

## Objetivo: ¿Porqué robar Cookies?
Analogía del Sistema de Autenticación
* Login (usuario/contraseña)
* Cookie de sesión (PHPESSID)
* El problema de seguridad

Funcionamiento técnico

Nuestro objetivo de ataque
Usar XSS para extraer el valor de la cookie PHPSESSID de un usuario que ya está autenticado (idealmente un administrador). Unavez obtenido este token:
1. No necesitamos conocer la contraseña de la víctima.
2. No activamos alarmas de "inicio de sesión desde neuva ubicación"
3. Obtenemos todos los privilegios de la víctima instantáneamente
4. Podemos mantener el aceso hasta que expire la sesión (a veces días)

## Sesión Hijacking: El Plan de Ataque Completo
* Fase 1: Inyección del Payload 
* Fase 2: Activación del Exploit
* Fase 3: Exfiltración de Datos
* Fase 4: Suplantación de identidad
* Fase 5: Acceso total

## Práctica: Preparación del Entorno de ataque
Paso 1: Configurar DVWA
1. Iniciar sesión con credenciales predeterminadas:
   * Usuario: admin
   * Pass: password

## Detección de XSS: Proof of Concept
http://192.168.0.2/dvwa/login.php

![XSS](img-1.png)
![XSS](img-2.png)

# Link a clase 
https://www.youtube.com/watch?v=Vy56zcAtDq4 