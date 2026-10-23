# Phase E target - STOCK php:8.4.26-fpm, compiled defaults, NO php.ini / www.conf.
# memory_limit=128M, session.upload_progress=On, default FPM pool (pm=dynamic).
# Only the web endpoints and the session-plant helper are added.
FROM php:8.4.26-fpm

COPY webroot/ /var/www/html/
COPY plant_e.php /opt/exploit/plant_e.php
# default CMD: php-fpm
