# Phase C target - STOCK php:8.4.26-fpm, compiled defaults, NO php.ini / www.conf.
# Global session.serialize_handler stays at its default (`php`); the /app/
# directory flips to `php_serialize` via a per-directory .user.ini - which models
# a real application's behaviour and is the chain's precondition, not a server
# config change. The `Evil` __destruct gadget in /api/ is the other precondition.
#
# Relied-upon PHP *defaults*: upload_progress On, use_strict_mode 0,
# save_path -> /tmp, default FPM pool (pm=dynamic), user_ini.filename=.user.ini.
FROM php:8.4.26-fpm

COPY webroot/ /var/www/html/
# default CMD: php-fpm
