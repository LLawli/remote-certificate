//! O código de recuperação: a chave do banco escrita para uma pessoa guardar
//! fora da máquina, no formato de [`rede::codigo`].

use rede::codigo;
pub use rede::codigo::CodigoInvalido;
use zeroize::Zeroizing;

use crate::banco::{ChaveDoBanco, TAMANHO_DA_CHAVE};

/// A versão do formato, no começo do código.
const PREFIXO: &str = "RC1";
/// Quantos bytes do SHA-256 da chave conferem a digitação.
const CONFERENCIA: usize = 5;

pub fn codigo(chave: &ChaveDoBanco) -> Zeroizing<String> {
    codigo::escrever(PREFIXO, chave.expor(), CONFERENCIA)
}

/// A chave de volta de um código digitado. Aceita minúsculas, espaços e os
/// dígitos que se confundem com letras.
pub fn chave(digitado: &str) -> Result<ChaveDoBanco, CodigoInvalido> {
    let bytes = codigo::ler(PREFIXO, digitado, TAMANHO_DA_CHAVE, CONFERENCIA)?;
    let mut chave = ChaveDoBanco::zerado().map_err(|_| CodigoInvalido::Formato)?;
    chave.expor_mut().copy_from_slice(&bytes);
    Ok(chave)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_codigo_devolve_a_mesma_chave() {
        let original = ChaveDoBanco::aleatorio().unwrap();
        let escrito = codigo(&original);
        assert!(escrito.starts_with("RC1-"));
        assert_eq!(chave(&escrito).unwrap().expor(), original.expor());

        // Como uma pessoa digita: minúsculas, espaços no lugar dos hífens.
        let digitado = escrito.to_lowercase().replace('-', " ");
        assert_eq!(chave(&digitado).unwrap().expor(), original.expor());
    }

    #[test]
    fn um_caractere_trocado_e_pego() {
        let escrito = codigo(&ChaveDoBanco::aleatorio().unwrap());
        let mut trocado = escrito.as_bytes().to_vec();
        // Um caractere no meio da chave, trocado por outro do alfabeto.
        let i = 10;
        trocado[i] = if trocado[i] == b'A' { b'B' } else { b'A' };
        let trocado = String::from_utf8(trocado).unwrap();
        assert_eq!(chave(&trocado).err(), Some(CodigoInvalido::Conferencia));
        assert_eq!(chave("RC1-AAAA").err(), Some(CodigoInvalido::Formato));
        assert_eq!(chave("qualquer coisa").err(), Some(CodigoInvalido::Formato));
    }
}
