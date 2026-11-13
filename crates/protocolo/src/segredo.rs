use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Um PIN, uma senha ou um OTP.
///
/// Não aparece em `Debug`, para não vazar em log, e é apagado da memória ao
/// sair de escopo. O apagamento é o melhor esforço: as cópias que o
/// `serde_json` faz ao ler a linha não passam por aqui.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Segredo(String);

impl Segredo {
    pub fn novo(valor: String) -> Self {
        Self(valor)
    }

    pub fn expor(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Segredo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Segredo(***)")
    }
}

impl Drop for Segredo {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn debug_nao_mostra_o_valor() {
        let pin = Segredo::novo("123456".into());
        assert_eq!(format!("{pin:?}"), "Segredo(***)");
        assert_eq!(pin.expor(), "123456");
    }
}
