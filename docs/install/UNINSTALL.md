# Uninstall y factory reset

M5.2 define uninstall como retiro de programa y unidades, no como borrado de
la identidad del Host.

El uninstall normal detiene/deshabilita el servicio y elimina los archivos de
programa del canal. Conserva `/var/lib/actium`, `/etc/actium`, la Host
Identity, Trust Store, grants y estado operativo para permitir recuperación o
reinstalación segura.

Factory reset es una operación distinta, deliberada y todavía fuera del
alcance de M5.2. No debe inferirse ni ejecutarse desde uninstall.
