# Phase D target - STOCK php:8.4.26-apache, out-of-the-box config.
# NO php.ini (compiled default memory_limit=128M, session.upload_progress=On),
# prefork mod_php. The only addition is a one-line endpoint for the exploit to
# drive - nothing about the vulnerability is configured here.
FROM php:8.4.26-apache

RUN printf '<?php // Silence is golden.\n' > /var/www/html/index.php
# default CMD: apache2-foreground
