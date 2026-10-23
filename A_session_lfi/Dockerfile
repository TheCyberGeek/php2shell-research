# Phase A target - STOCK php:8.4.26-apache, compiled defaults, NO php.ini.
# The only thing added is the vulnerable app (an LFI sink) - that is the chain's
# precondition, not a PHP config change.
#
# Relied-upon PHP *defaults* (not customised here):
#   session.upload_progress.enabled = On     (default since 5.4)
#   session.use_strict_mode         = 0       (default -> attacker may choose the SID)
#   session.save_path               = <empty> (default -> /tmp, so sess_<sid> is in /tmp)
#   session.upload_progress.cleanup = On      (default -> exploit uses the stalled writer)
FROM php:8.4.26-apache

COPY webroot/ /var/www/html/
# default CMD: apache2-foreground
