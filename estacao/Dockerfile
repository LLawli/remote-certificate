# O pacote da estação, compilado no Ubuntu 24.04: a glibc (2.39), o GTK 4.14 e
# a libadwaita 1.5 mais antigos que ele precisa aceitar. Compilado numa
# distribuição mais nova, o módulo PKCS#11 não carrega numa mais velha.
#
#   docker build -f estacao/Dockerfile --output target/estacao .
FROM docker.io/library/ubuntu:24.04 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gcc libc6-dev pkg-config libgtk-4-dev libadwaita-1-dev \
    && rm -rf /var/lib/apt/lists/*
# A versão mínima do projeto (rust-version), como na imagem do servidor.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.92
ENV PATH=/root/.cargo/bin:$PATH
WORKDIR /src
ARG CARGO_BUILD_JOBS
COPY . .
RUN cargo build --release --locked -p agente -p janela -p pkcs11 \
    && d=/out/remote-certificate-estacao \
    && install -Dm755 target/release/remote-certificate-agente "$d/bin/remote-certificate-agente" \
    && install -Dm755 target/release/remote-certificate-dialogo "$d/bin/remote-certificate-dialogo" \
    && install -Dm644 target/release/libremote_certificate_pkcs11.so \
        "$d/lib/libremote_certificate_pkcs11.so" \
    && install -Dm755 estacao/instalar.sh "$d/instalar.sh" \
    && install -Dm644 estacao/remote-certificate-agente.service \
        "$d/remote-certificate-agente.service" \
    && tar -C /out -czf /out/remote-certificate-estacao-x86_64.tar.gz remote-certificate-estacao

# Só os arquivos, para o `--output`: não é uma imagem que roda.
FROM scratch
COPY --from=build /out/ /
