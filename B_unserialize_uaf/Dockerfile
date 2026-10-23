# Phase B target - STOCK php:8.4.26-apache, compiled defaults, NO php.ini.
# The UAF->write escalation runs in the target's own process context, so the
# exploit is baked in and invoked with `docker compose exec`. No config needed;
# prove the disable_functions bypass at run time with `php -d disable_functions=...`.
FROM php:8.4.26-apache

COPY chain_b_auto.php chain_b_uaf_rce.php /opt/exploit/
# default CMD: apache2-foreground
