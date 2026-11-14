#!/usr/bin/env bash
# Um servidor e uma estação inteiros nesta máquina, pelas CLIs de verdade:
# o servidor falso do RemoteID, o remote-certificate com o driver RemoteID, o
# agente pareado e o módulo PKCS#11. Serve para conferir a face com programas
# reais (pkcs11-tool, p11tool, Firefox) e é a base das VMs da estação.
#
#   scripts/laboratorio.sh            # sobe tudo e espera o Ctrl+C
#   SO_SERVIDOR=1 scripts/laboratorio.sh
#                                     # só o servidor, para a estação de uma VM;
#                                     # target/laboratorio/parear dá um código
#
# Para uma VM, um túnel reverso (`ssh -N -R 18443:127.0.0.1:18443 <vm>`) leva
# a porta ao 127.0.0.1 de dentro dela sem abrir o firewall do host. ESCUTA
# muda o endereço quando a estação está em outra máquina da rede.
#
# Em outro terminal, `source target/laboratorio/ambiente` e use o módulo em
# $MODULO. O PIN pessoal é $PIN_PESSOAL; a janela do OTP responde sozinha o
# código do servidor falso.
set -euo pipefail
cd "$(dirname "$0")/.."

PORTA=${PORTA:-18443}
# Onde o servidor escuta.
ESCUTA=${ESCUTA:-127.0.0.1}
# Quanto o login do PIN pessoal dura sem uso, em segundos (o padrão é 15 min).
SESSAO=${SESSAO:-900}
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
servidor servir --endereco "$ESCUTA:$PORTA" --sessao "$SESSAO" --drivers "$alvo" "${banco[@]}" \
    2>"$lab/servidor.log" &
filhos+=($!)
for _ in $(seq 50); do grep -q atendendo "$lab/servidor.log" && break; sleep 0.1; done

# Um código de pareamento novo a cada chamada, para a estação de outra máquina.
cat >"$lab/parear" <<EOF
#!/bin/sh
exec "$alvo/remote-certificate" dispositivo parear maria "\${1:-estacao}" \\
    --banco "$lab/banco.db" --chave "$lab/chave"
EOF
chmod 700 "$lab/parear"
if [[ -n ${SO_SERVIDOR:-} ]]; then
    echo "servidor pronto em $ESCUTA:$PORTA; código: $lab/parear (Ctrl+C encerra)" >&2
    wait
    exit 0
fi

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
    "$alvo/remote-certificate-agente" parear "$ESCUTA:$PORTA" >&2
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
