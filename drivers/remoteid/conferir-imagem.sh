#!/usr/bin/env bash
# Confere a imagem do driver RemoteID como ela roda em produção: o compose.yaml
# do projeto (só leitura, sem capabilities, no-new-privileges), o `remoteid`
# da release dentro da imagem e cada driver isolado pelo lançador. O servidor
# falso do RemoteID-linux faz a Certisign na porta 443, e uma estação nesta
# máquina (o agente e o módulo PKCS#11) assina pelo `pkcs11-tool`; a
# assinatura é conferida com o `openssl`.
#
#   docker build -t remote-certificate .
#   docker build -f drivers/remoteid/Dockerfile -t remote-certificate-remoteid .
#   drivers/remoteid/conferir-imagem.sh
#
# Precisa do Docker com o compose, do pkcs11-tool (OpenSC), do openssl e do jq.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGEM=${IMAGEM:-remote-certificate-remoteid}
PORTA=${PORTA:-18444}
PIN_PESSOAL=pessoal-2468
# Os dados de teste do servidor falso do RemoteID-linux.
EMAIL=teste@remoteid.local
SENHA=teste-1234
OTP=123456

for programa in docker pkcs11-tool openssl jq; do
    command -v "$programa" >/dev/null || { echo "falta o $programa" >&2; exit 1; }
done
eval "$(scripts/remoteid.sh)"
cargo build --quiet --locked --bin remote-certificate-agente >&2
cargo build --quiet --locked -p pkcs11 >&2
alvo=$PWD/target/debug

dir=$PWD/target/conferir-imagem
projeto=rc-conferir-imagem
mock=$projeto-mock
rm -rf "$dir"
mkdir -p "$dir/execucao"
chmod 700 "$dir/execucao"

agente=
encerrar() {
    [[ -n $agente ]] && kill "$agente" 2>/dev/null
    compor down -v >/dev/null 2>&1 || true
    docker rm -f "$mock" >/dev/null 2>&1 || true
}
trap encerrar EXIT

# Uma chave de teste: o usuário do container (uid 10001) lê pelo bind do secret.
head -c 32 /dev/urandom >"$dir/chave"
chmod 644 "$dir/chave"

# O servidor falso escuta só no 127.0.0.1 do container dele; o servidor entra
# na mesma rede, e a porta 8443 sai para cá pelo container do falso.
docker run -d --name "$mock" -p "127.0.0.1:$PORTA:8443" \
    -v "$REMOTEID_MOCK_BIN:/mock:ro" --entrypoint /mock "$IMAGEM" 443 >/dev/null

cat >"$dir/compose.override.yaml" <<EOF
services:
  remote-certificate:
    network_mode: container:$mock
    # Na rede de outro container, o nome da máquina é o dele.
    hostname: !reset null
    ports: !reset []
EOF
compor() {
    IMAGEM=$IMAGEM TAG=latest CHAVE=$dir/chave docker compose -p "$projeto" \
        -f compose.yaml -f "$dir/compose.override.yaml" "$@"
}
servidor() { compor run --rm -T remote-certificate "$@"; }

servidor token criar RemoteID remote-certificate-driver-remoteid -- \
    --servidor http://127.0.0.1:443 >&2
printf '%s\n%s\n' "$EMAIL" "$SENHA" | servidor token configurar RemoteID 2>"$dir/configurar.log" >&2
cat "$dir/configurar.log" >&2
grep -q "isolar: remote-certificate-driver-remoteid: Landlock completo" "$dir/configurar.log" \
    || { echo "o driver não subiu isolado" >&2; exit 1; }
echo "$PIN_PESSOAL" | servidor usuario criar maria >&2

compor up -d >&2
for _ in $(seq 100); do compor logs 2>&1 | grep -q atendendo && break; sleep 0.1; done
conteiner=$(compor ps -q remote-certificate)
inspecao=$(docker inspect "$conteiner")
jq -e '.[0].HostConfig | .ReadonlyRootfs and (.CapDrop == ["ALL"])
    and (.SecurityOpt | index("no-new-privileges:true"))' <<<"$inspecao" >/dev/null \
    || { echo "o container não está endurecido como o compose.yaml manda" >&2; exit 1; }

# A estação: o agente pareado, com a janela do OTP respondendo sozinha.
cat >"$dir/janela" <<EOF
#!/bin/sh
cat >/dev/null
echo '{"valores":{"otp":"$OTP"}}'
EOF
chmod 700 "$dir/janela"
export REMOTE_CERTIFICATE_DADOS=$dir/agente
export REMOTE_CERTIFICATE_AGENTE=$dir/execucao/agente.sock
export REMOTE_CERTIFICATE_DIALOGO=$dir/janela
compor exec -T remote-certificate remote-certificate dispositivo parear maria conferir 2>/dev/null |
    "$alvo/remote-certificate-agente" parear "127.0.0.1:$PORTA" >&2
"$alvo/remote-certificate-agente" servir 2>"$dir/agente.log" &
agente=$!
for _ in $(seq 50); do [[ -S $REMOTE_CERTIFICATE_AGENTE ]] && break; sleep 0.1; done

modulo=$alvo/libremote_certificate_pkcs11.so
echo "documento de teste" >"$dir/documento"
pkcs11-tool --module "$modulo" --login --pin "$PIN_PESSOAL" --sign \
    --mechanism SHA256-RSA-PKCS --input-file "$dir/documento" \
    --output-file "$dir/assinatura" >&2
pkcs11-tool --module "$modulo" --list-objects --type cert >"$dir/objetos" 2>&1
id=$(awk '$1 == "ID:" { print $2; exit }' "$dir/objetos")
test -n "$id" || { cat "$dir/objetos" >&2; echo "o certificado não apareceu" >&2; exit 1; }
pkcs11-tool --module "$modulo" --read-object --type cert --id "$id" \
    --output-file "$dir/certificado.der" >&2
openssl x509 -inform der -in "$dir/certificado.der" -pubkey -noout >"$dir/publica.pem"
openssl dgst -sha256 -verify "$dir/publica.pem" -signature "$dir/assinatura" "$dir/documento"

compor logs 2>&1 | grep isolar >&2
echo "imagem $IMAGEM conferida: o driver isolado assinou no container endurecido" >&2
