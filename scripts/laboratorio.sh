#!/usr/bin/env bash
# Um servidor e uma estação inteiros nesta máquina, pelas CLIs de verdade:
# o servidor falso do RemoteID, o remote-certificate com o driver RemoteID, o
# agente pareado e o módulo PKCS#11. Serve para conferir a face com programas
# reais (pkcs11-tool, p11tool, Firefox) e é a base das VMs da estação.
#
#   scripts/laboratorio.sh            # sobe tudo e espera o Ctrl+C
#
# Em outro terminal, `source target/laboratorio/ambiente` e use o módulo em
# $MODULO. O PIN pessoal é $PIN_PESSOAL; a janela do OTP responde sozinha o
# código do servidor falso.
set -euo pipefail
cd "$(dirname "$0")/.."

PORTA=${PORTA:-18443}
PIN_PESSOAL=${PIN_PESSOAL:-pessoal-2468}
# Os dados de teste do servidor falso do RemoteID-linux.
EMAIL=teste@remoteid.local
SENHA=teste-1234
OTP=123456

remoteid=$(scripts/remoteid.sh)
eval "$remoteid"
cargo build --quiet --locked --bin remote-certificate --bin remote-certificate-agente \
    --bin remote-certificate-driver-remoteid >&2
cargo build --quiet --locked -p pkcs11 >&2
alvo=$PWD/target/debug
for artefato in remote-certificate remote-certificate-agente \
    remote-certificate-driver-remoteid libremote_certificate_pkcs11.so; do
    test -s "$alvo/$artefato" || { echo "não achei $alvo/$artefato" >&2; exit 1; }
done

lab=$PWD/target/laboratorio
rm -rf "$lab"
mkdir -p "$lab/estado" "$lab/execucao"
chmod 700 "$lab/execucao"

filhos=()
encerrar() {
    for pid in "${filhos[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap encerrar EXIT

# O servidor falso escreve a URL na primeira linha.
"$REMOTEID_MOCK_BIN" 0 >"$lab/mock.url" 2>/dev/null &
filhos+=($!)
for _ in $(seq 50); do [[ -s $lab/mock.url ]] && break; sleep 0.1; done
mock=$(head -n1 "$lab/mock.url")
test -n "$mock" || { echo "o servidor falso não subiu" >&2; exit 1; }

banco=(--banco "$lab/banco.db" --chave "$lab/chave")
head -c 32 /dev/urandom >"$lab/chave"
chmod 600 "$lab/chave"
servidor() { "$alvo/remote-certificate" "$@"; }
servidor token criar RemoteID remote-certificate-driver-remoteid "${banco[@]}" -- \
    --estado "$lab/estado" --remoteid "$REMOTEID_BIN" --servidor "$mock" >&2
printf '%s\n%s\n' "$EMAIL" "$SENHA" |
    servidor token configurar RemoteID --drivers "$alvo" "${banco[@]}" >&2
echo "$PIN_PESSOAL" | servidor usuario criar maria "${banco[@]}" >&2
servidor servir --endereco "127.0.0.1:$PORTA" --drivers "$alvo" "${banco[@]}" \
    2>"$lab/servidor.log" &
filhos+=($!)
for _ in $(seq 50); do grep -q atendendo "$lab/servidor.log" && break; sleep 0.1; done

# A janela do OTP do laboratório: responde o código do servidor falso.
cat >"$lab/janela" <<EOF
#!/bin/sh
cat >>"$lab/perguntas"
echo >>"$lab/perguntas"
echo '{"valores":{"otp":"$OTP"}}'
EOF
chmod 700 "$lab/janela"

export REMOTE_CERTIFICATE_DADOS=$lab/agente
export REMOTE_CERTIFICATE_AGENTE=$lab/execucao/agente.sock
export REMOTE_CERTIFICATE_DIALOGO=$lab/janela
export REMOTE_CERTIFICATE_REGISTRO=$lab/registro
servidor dispositivo parear maria laboratorio "${banco[@]}" 2>/dev/null |
    "$alvo/remote-certificate-agente" parear "127.0.0.1:$PORTA" >&2
"$alvo/remote-certificate-agente" servir 2>"$lab/agente.log" &
filhos+=($!)
for _ in $(seq 50); do [[ -S $REMOTE_CERTIFICATE_AGENTE ]] && break; sleep 0.1; done
test -S "$REMOTE_CERTIFICATE_AGENTE" || { echo "o agente não subiu" >&2; exit 1; }

cat >"$lab/ambiente" <<EOF
export REMOTE_CERTIFICATE_AGENTE=$REMOTE_CERTIFICATE_AGENTE
export REMOTE_CERTIFICATE_REGISTRO=$REMOTE_CERTIFICATE_REGISTRO
export MODULO=$alvo/libremote_certificate_pkcs11.so
export PIN_PESSOAL=$PIN_PESSOAL
EOF
echo "laboratório pronto: source $lab/ambiente (Ctrl+C encerra)" >&2
wait
