//! O que o servidor e os clientes compartilham na rede: o mTLS com chaves
//! fixadas, o pareamento e os códigos que uma pessoa copia. O desenho está em
//! `docs/arquitetura.md`.

pub mod agente;
pub mod api;
pub mod codigo;
pub mod pareamento;
pub mod tls;
