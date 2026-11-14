#!/bin/sh
# Instala a estação para este usuário, sem root: o agente, a janela do OTP e o
# módulo PKCS#11 em ~/.local, o módulo registrado no p11-kit do usuário e o
# agente como serviço do systemd do usuário.
#
#   ./instalar.sh            # instala (ou atualiza)
#   ./instalar.sh remover    # desinstala; o pareamento fica
set -eu
cd "$(dirname "$0")"

bin=$HOME/.local/bin
lib=$HOME/.local/lib/remote-certificate
config=${XDG_CONFIG_HOME:-$HOME/.config}
modulo=$config/pkcs11/modules/remote-certificate.module
unit=$config/systemd/user/remote-certificate-agente.service

if [ "${1:-}" = remover ]; then
    systemctl --user disable --now remote-certificate-agente.service 2>/dev/null || true
    rm -f "$bin/remote-certificate-agente" "$bin/remote-certificate-dialogo" \
        "$lib/libremote_certificate_pkcs11.so" "$modulo" "$unit"
    rmdir "$lib" 2>/dev/null || true
    systemctl --user daemon-reload
    echo "removido; o pareamento continua em ~/.local/share/remote-certificate"
    exit 0
fi

install -Dm755 bin/remote-certificate-agente "$bin/remote-certificate-agente"
install -Dm755 bin/remote-certificate-dialogo "$bin/remote-certificate-dialogo"
install -Dm644 lib/libremote_certificate_pkcs11.so "$lib/libremote_certificate_pkcs11.so"
mkdir -p "$(dirname "$modulo")"
# critical: no, para um defeito do módulo não derrubar os outros tokens.
printf 'module: %s\ncritical: no\n' "$lib/libremote_certificate_pkcs11.so" >"$modulo"
mkdir -p "$(dirname "$unit")"
sed "s|@BIN@|$bin|" remote-certificate-agente.service >"$unit"
systemctl --user daemon-reload
systemctl --user enable remote-certificate-agente.service

if "$bin/remote-certificate-agente" estado | grep -q '^pareado'; then
    systemctl --user restart remote-certificate-agente.service
    echo "instalado e atualizado"
else
    echo "instalado. Para parear, cole o código que o administrador gerou:"
    echo "  $bin/remote-certificate-agente parear <servidor:porta>"
    echo "  systemctl --user start remote-certificate-agente"
fi
