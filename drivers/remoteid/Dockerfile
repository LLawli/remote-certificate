# A imagem do servidor com o driver do RemoteID, derivada da imagem base:
#
#   docker build -t remote-certificate .
#   docker build -f drivers/remoteid/Dockerfile -t remote-certificate-remoteid .
#
# O token: `token criar <nome> remote-certificate-driver-remoteid`.
ARG BASE=remote-certificate:latest

# O driver, compilado do mesmo código da imagem base.
FROM rust:1.92-slim-trixie AS build
WORKDIR /src
# Vazio usa todos os núcleos; numa máquina compartilhada, --build-arg limita.
ARG CARGO_BUILD_JOBS
COPY . .
RUN cargo build --release --locked -p driver-remoteid \
    && install -D target/release/remote-certificate-driver-remoteid \
        /out/remote-certificate-driver-remoteid

# O `remoteid` estático do pacote de servidor do RemoteID-linux. A versão e o
# SHA-256 andam juntos; o 0.5.2 é o primeiro que se protege sozinho
# (docs/seguranca.md).
FROM debian:trixie-slim AS remoteid
ARG REMOTEID_VERSAO=0.5.2
ARG REMOTEID_SHA256=ba785408f162630fd0101a5e7f97654a5f7146df48f55d1709d79e4cd37a0988
ADD --checksum=sha256:${REMOTEID_SHA256} \
    https://github.com/LLawli/RemoteID-linux/releases/download/v${REMOTEID_VERSAO}/remoteid-servidor-x86_64.tar.gz \
    /remoteid.tar.gz
RUN mkdir /out && tar xzf /remoteid.tar.gz -C /out && test -x /out/bin/remoteid

# O driver procura o `remoteid` na própria pasta; o manifesto diz ao
# lançador o que ele precisa (a Certisign, na 443).
FROM ${BASE}
COPY --from=build /out/remote-certificate-driver-remoteid /drivers/
COPY --from=remoteid /out/bin/remoteid /drivers/remoteid
COPY drivers/remoteid/remote-certificate-driver-remoteid.manifesto.json /drivers/
