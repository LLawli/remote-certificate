# Compilação: toolchain completa, nada disto vai para a imagem final.
FROM rust:1.92-slim-trixie AS build
# perl e make compilam o OpenSSL que vai junto com o SQLCipher.
RUN apt-get update \
    && apt-get install -y --no-install-recommends perl make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Vazio usa todos os núcleos; numa máquina compartilhada, --build-arg limita.
ARG CARGO_BUILD_JOBS
COPY . .
RUN cargo build --release --locked -p servidor \
    && install -D target/release/remote-certificate /out/remote-certificate

# Final: glibc, porque os módulos PKCS#11 dos fornecedores de token são glibc.
# Nenhum driver vem junto: cada um tem a imagem derivada dele (drivers/<nome>/).
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /dados --no-create-home certificado \
    && install -d -o certificado -g certificado -m 0700 /dados \
    && install -d -m 0755 /drivers
COPY --from=build /out/remote-certificate /usr/local/bin/remote-certificate
USER certificado
VOLUME ["/dados"]
ENTRYPOINT ["/usr/local/bin/remote-certificate"]
