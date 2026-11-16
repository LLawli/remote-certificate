# A imagem do servidor com o driver da GD Burti: o driver e o SafeSign IC
# (A.E.T. Europe), o módulo PKCS#11 oficial dos tokens. Construída a partir da
# raiz do repositório, sobre a imagem anterior em BASE (bin/deploy):
#
#   docker build -f drivers/gd-burti/Dockerfile -t remote-certificate-gd-burti .
#
# O token: `token criar <nome> remote-certificate-driver-gd-burti`. O pcscd fica
# no host, e o compose monta o /run/pcscd dele no container.
ARG BASE=remote-certificate:latest

# O driver.
FROM rust:1.92-slim-trixie AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS
COPY . .
RUN cargo build --release --locked -p driver-gd-burti \
    && install -D target/release/remote-certificate-driver-gd-burti \
        /out/remote-certificate-driver-gd-burti

# O SafeSign, do link oficial e conferido pelo SHA-256 (o mesmo pacote e o
# mesmo hash da receita do Tessera). Só os arquivos do pacote: nenhum script
# do mantenedor roda, e o /etc fica de fora. Entram o módulo PKCS#11
# (libaetpkss), a biblioteca do cartão que ele carrega pelo nome (libaetjcss),
# a libaetdlss e os dados em /usr/share/safesign; o Token Administration e a
# libaetdlglib, que são gráficos (wxWidgets), não.
FROM debian:trixie-slim AS safesign
ADD --checksum=sha256:7742e21e3141e51e307d7613b4046886bc7c4aa203835dcf5c43cd348f2a1b91 \
    https://assets.ctfassets.net/zuadwp3l2xby/6vGICRnQgQ8TkcHTgcouIr/5acf96dcbc0364aa9228606d3969ef97/SafeSignICStandardLinux4.5.0.0-AET.000ub2404x86_64.deb \
    /safesign.deb
RUN dpkg-deb -x /safesign.deb /pacote \
    && mkdir -p /out/usr/lib /out/usr/share \
    && cp -a /pacote/usr/lib/libaetpkss.so* /pacote/usr/lib/libaetjcss.so* \
        /pacote/usr/lib/libaetdlss.so* /out/usr/lib/ \
    && cp -a /pacote/usr/share/safesign /out/usr/share/ \
    && test -f /out/usr/lib/libaetpkss.so.3.9.33.1 \
    && test -e /out/usr/lib/libaetpkss.so.3

FROM ${BASE}
USER root
# O que o libaetpkss.so pede (readelf -d): o GDBM (o Tessera o baixa do
# Ubuntu porque o runtime do Flatpak não tem; aqui vem do Debian), o cliente
# do PC/SC, o OpenSSL 3 e a libstdc++. O pcscd fica no host.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgdbm-compat4t64 libpcsclite1 libssl3t64 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=safesign /out/ /
COPY --from=build /out/remote-certificate-driver-gd-burti /drivers/
# O manifesto deixa o driver conectar no socket do pcscd, e só nele.
COPY drivers/gd-burti/remote-certificate-driver-gd-burti.manifesto.json /drivers/
USER certificado
