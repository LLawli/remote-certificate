//! O código de recuperação: a chave do banco escrita para uma pessoa guardar
//! fora da máquina. Base32 (sem 0, 1 e 8, que se confundem com O, I e B), em
//! grupos de quatro, com os primeiros bytes do SHA-256 da chave no fim para
//! pegar um erro de digitação.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::banco::{ChaveDoBanco, TAMANHO_DA_CHAVE};

/// A versão do formato, no começo do código.
const PREFIXO: &str = "RC1";
/// Quantos bytes do SHA-256 da chave conferem a digitação.
const CONFERENCIA: usize = 5;
const GRUPO: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum CodigoInvalido {
    /// Não é um código deste formato (ou falta um pedaço).
    Formato,
    /// O código tem o formato certo, mas não confere: um erro de digitação.
    Conferencia,
}

pub fn codigo(chave: &ChaveDoBanco) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(TAMANHO_DA_CHAVE + CONFERENCIA));
    bytes.extend_from_slice(chave.expor());
    bytes.extend_from_slice(&Sha256::digest(chave.expor())[..CONFERENCIA]);
    let corrido = Zeroizing::new(BASE32_NOPAD.encode(&bytes));
    let mut codigo = Zeroizing::new(String::from(PREFIXO));
    for grupo in corrido.as_bytes().chunks(GRUPO) {
        codigo.push('-');
        codigo.push_str(std::str::from_utf8(grupo).expect("Base32 é ASCII"));
    }
    codigo
}

/// A chave de volta de um código digitado. Aceita minúsculas, espaços e os
/// dígitos que se confundem com letras.
pub fn chave(digitado: &str) -> Result<ChaveDoBanco, CodigoInvalido> {
    // O prefixo sai antes da troca de dígitos por letras: ele tem um `1`.
    let digitado = digitado.trim_start();
    let corpo = digitado
        .get(..PREFIXO.len())
        .filter(|p| p.eq_ignore_ascii_case(PREFIXO))
        .map(|_| &digitado[PREFIXO.len()..])
        .ok_or(CodigoInvalido::Formato)?;
    let limpo: Zeroizing<String> = Zeroizing::new(
        corpo
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                '0' => 'O',
                '1' => 'I',
                '8' => 'B',
                c => c,
            })
            .collect(),
    );
    let bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(limpo.as_bytes())
            .map_err(|_| CodigoInvalido::Formato)?,
    );
    if bytes.len() != TAMANHO_DA_CHAVE + CONFERENCIA {
        return Err(CodigoInvalido::Formato);
    }
    let (crua, conferencia) = bytes.split_at(TAMANHO_DA_CHAVE);
    if Sha256::digest(crua)[..CONFERENCIA] != *conferencia {
        return Err(CodigoInvalido::Conferencia);
    }
    let mut chave = ChaveDoBanco::zerado().map_err(|_| CodigoInvalido::Formato)?;
    chave.expor_mut().copy_from_slice(crua);
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
