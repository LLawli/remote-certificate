#!/usr/bin/env bash
# Roda como root no host, por `bin/deploy chave`. Gera a chave do banco no
# próprio host, selada no TPM (ela nunca passa em claro pelo disco nem pela
# rede), instala o serviço que a abre em /run a cada boot e mostra o código de
# recuperação uma vez. Com --restaurar, a chave vem de um código de recuperação.
#
#   chave.sh <imagem> [--restaurar]
set -euo pipefail

nome=remote-certificate-chave
cred=/etc/credstore.encrypted/$nome.cred
imagem=${1:?uso: chave.sh <imagem> [--restaurar]}
modo=${2:-}
dir=$(dirname "$0")

if [[ -e $cred ]]; then
    echo "$cred já existe: uma chave em uso não é trocada por aqui" >&2
    exit 1
fi
if systemd-creds has-tpm2 >/dev/null 2>&1; then
    selo=host+tpm2
else
    selo=host
    echo "aviso: sem TPM2; a chave fica selada só com /var/lib/systemd/credential.secret" >&2
fi

# O container que lê e mostra o código: sem rede, sem escrita, sem privilégio.
isolado=(docker run --rm --network none --read-only --cap-drop ALL
    --security-opt no-new-privileges:true)

install -d -m 0700 /etc/credstore.encrypted
if [[ $modo == --restaurar ]]; then
    printf 'Código de recuperação: ' >&2
    "${isolado[@]}" -i "$imagem" recuperacao restaurar \
        | systemd-creds encrypt --with-key="$selo" --name="$nome" - "$cred"
else
    head -c 32 /dev/urandom \
        | systemd-creds encrypt --with-key="$selo" --name="$nome" - "$cred"
fi
chmod 0600 "$cred"

install -m 0644 "$dir/$nome.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now "$nome.service"

if [[ $modo != --restaurar ]]; then
    "${isolado[@]}" -it -v "/run/remote-certificate/chave:/run/secrets/$nome:ro" \
        "$imagem" recuperacao mostrar
fi
