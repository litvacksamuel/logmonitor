# logmonitor
Esta aplicación desarrollada en NodeJS con la implementación de websockets, tiene como finalidad facilitar la auditoria y el control de requests 
que llegan a un servidor web, ya sea apache o nginx. Ademas, tendrá la funcionalidad de bloquear una IP mediante una regla de IPTABLES si esta es considerada una amenaza 
según el nivel de riesgo detectado, el body de la solicitud y la frecuencia de peticiones por segundo de dicha IP. Contemplara los ataques web más conocidos, incluyendo los filtros WAF usualmente utilizados y ennumerados en el listado OWASP de Web Aplicación Firewall Bypass.

Se espera que la aplicacion detecte los siguientes ataques:<br>
Cross Site Scripting (XSS)<br>
SQL Injection (SQLi)<br>
DDoS (Distributed denial of service)

<img src="https://i.ibb.co/PjdDyDs/logmonitor.png">
