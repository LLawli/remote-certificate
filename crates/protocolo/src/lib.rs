//! Contrato entre o servidor e um driver de token.
//!
//! Um driver é um executável à parte, instalado só por quem tem aquele token.
//! O servidor o lança e conversa com ele em JSON, uma mensagem por linha, pelo
//! stdin e pelo stdout do driver. O formato completo está em `docs/drivers.md`.

mod b64;
mod linha;
mod mecanismo;
mod mensagem;
mod segredo;

pub use linha::{LINHA_MAXIMA, ler_linha};
pub use mecanismo::{Mecanismo, suporta_tls13};
pub use mensagem::{
    Apresentacao, Assinatura, Campo, Chave, Configurado, Erro, Fator, Listagem, MensagemDoDriver,
    Operacao, Pedido, PedidoDeFatores, RespostaDeFatores, TipoDeErro, TipoDeFator,
};
pub use segredo::Segredo;

/// Versão do contrato. Muda quando uma mensagem muda de forma incompatível.
pub const VERSAO: u32 = 0;
