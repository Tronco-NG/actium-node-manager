#!/bin/sh
set -e

# Configurar permisos de ejecución de recursos
chmod 0755 "/usr/lib/Actium Node Manager/resources/supervisor/actium-node-supervisor" 2>/dev/null || true
chmod 0755 "/usr/lib/Actium Node Manager/resources/supervisor/install-supervisor-debian.sh" 2>/dev/null || true
chmod 0755 "/usr/lib/actium-node-manager/resources/supervisor/actium-node-supervisor" 2>/dev/null || true
chmod 0755 "/usr/lib/actium-node-manager/resources/supervisor/install-supervisor-debian.sh" 2>/dev/null || true

# Auto-aprovisionar y habilitar Actium Node Supervisor Stable con systemd si está disponible
SCRIPT=""
if [ -x "/usr/lib/Actium Node Manager/resources/supervisor/install-supervisor-debian.sh" ]; then
    SCRIPT="/usr/lib/Actium Node Manager/resources/supervisor/install-supervisor-debian.sh"
elif [ -x "/usr/lib/actium-node-manager/resources/supervisor/install-supervisor-debian.sh" ]; then
    SCRIPT="/usr/lib/actium-node-manager/resources/supervisor/install-supervisor-debian.sh"
fi

if [ -n "$SCRIPT" ] && [ -d /run/systemd/system ]; then
    echo "Configurando e iniciando Actium Node Supervisor (Stable)..."
    "$SCRIPT" --channel stable --install || true
fi
