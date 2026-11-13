//! Códigos para uma pessoa copiar ou digitar: um prefixo com a versão do
//! formato, os bytes em Base32 (sem 0, 1 e 8, que se confundem com O, I e B)
//! em grupos de quatro, e os primeiros bytes do SHA-256 deles no fim para pegar
//! um erro de digitação.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const GRUPO: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum CodigoInvalido {
    /// Não é um código deste formato (ou falta um pedaço).
    Formato,
    /// O código tem o formato certo, mas não confere: um erro de digitação.
    Conferencia,
}

/// `bytes` escritos com `prefixo` e `conferencia` bytes de conferência.
pub fn escrever(prefixo: &str, bytes: &[u8], conferencia: usize) -> Zeroizing<String> {
    let mut tudo = Zeroizing::new(Vec::with_capacity(bytes.len() + conferencia));
    tudo.extend_from_slice(bytes);
    tudo.extend_from_slice(&Sha256::digest(bytes)[..conferencia]);
    let corrido = Zeroizing::new(BASE32_NOPAD.encode(&tudo));
    let mut codigo = Zeroizing::new(String::from(prefixo));
    for grupo in corrido.as_bytes().chunks(GRUPO) {
        codigo.push('-');
        codigo.push_str(std::str::from_utf8(grupo).expect("Base32 é ASCII"));
    }
    codigo
}

/// Os `tamanho` bytes de volta de um código digitado. Aceita minúsculas,
/// espaços e os dígitos que se confundem com letras.
pub fn ler(
    prefixo: &str,
    digitado: &str,
    tamanho: usize,
    conferencia: usize,
) -> Result<Zeroizing<Vec<u8>>, CodigoInvalido> {
    // O prefixo sai antes da troca de dígitos por letras: ele tem um `1`.
    let digitado = digitado.trim_start();
    let corpo = digitado
        .get(..prefixo.len())
        .filter(|p| p.eq_ignore_ascii_case(prefixo))
        .map(|_| &digitado[prefixo.len()..])
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
    let mut bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(limpo.as_bytes())
            .map_err(|_| CodigoInvalido::Formato)?,
    );
    if bytes.len() != tamanho + conferencia {
        return Err(CodigoInvalido::Formato);
    }
    if Sha256::digest(&bytes[..tamanho])[..conferencia] != bytes[tamanho..] {
        return Err(CodigoInvalido::Conferencia);
    }
    bytes.truncate(tamanho);
    Ok(bytes)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_codigo_devolve_os_mesmos_bytes() {
        let bytes = [7u8; 20];
        let escrito = escrever("XY1", &bytes, 3);
        assert!(escrito.starts_with("XY1-"));
        assert_eq!(*ler("XY1", &escrito, 20, 3).unwrap(), bytes);

        // Como uma pessoa digita: minúsculas, espaços no lugar dos hífens.
        let digitado = escrito.to_lowercase().replace('-', " ");
        assert_eq!(*ler("XY1", &digitado, 20, 3).unwrap(), bytes);
    }

    #[test]
    fn um_caractere_trocado_e_pego() {
        let escrito = escrever("XY1", &[9u8; 20], 3);
        let mut trocado = escrito.as_bytes().to_vec();
        let i = 10;
        trocado[i] = if trocado[i] == b'A' { b'B' } else { b'A' };
        let trocado = String::from_utf8(trocado).unwrap();
        assert_eq!(
            ler("XY1", &trocado, 20, 3).err(),
            Some(CodigoInvalido::Conferencia)
        );
        assert_eq!(
            ler("XY1", "XY1-AAAA", 20, 3).err(),
            Some(CodigoInvalido::Formato)
        );
        assert_eq!(
            ler("XY1", "ZZ1-AAAA", 20, 3).err(),
            Some(CodigoInvalido::Formato)
        );
    }
}
