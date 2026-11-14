//! A conversa entre o agente e a janela que pergunta à pessoa o fator que o
//! token pediu (o OTP): a [`Pergunta`] vai pelo stdin da janela, e os
//! [`Valores`] voltam pelo stdout. Fechar a janela (sair com erro) é
//! desistir.

use std::collections::BTreeMap;

use protocolo::Segredo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatorPedido {
    pub nome: String,
    /// Para a pessoa ler.
    pub rotulo: String,
}

/// O que a janela recebe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pergunta {
    pub fatores: Vec<FatorPedido>,
    /// Por que o token pede de novo (o código anterior foi recusado).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recusa: Option<String>,
    /// O certificado que vai assinar, como a pessoa o conhece.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificado: Option<String>,
}

/// O que a janela devolve.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Valores {
    pub valores: BTreeMap<String, Segredo>,
}
