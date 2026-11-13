use std::io::{self, BufRead, Read};

/// O tamanho máximo de uma linha do contrato, nos dois sentidos. Folgado para
/// uma lista de certificados; uma linha maior é de quem saiu do contrato, e
/// lê-la inteira deixaria um driver com defeito esgotar a memória de quem lê.
pub const LINHA_MAXIMA: usize = 1024 * 1024;

/// `read_line` com o limite de [`LINHA_MAXIMA`]: passou dele, é erro.
pub fn ler_linha(leitor: &mut impl BufRead, linha: &mut String) -> io::Result<usize> {
    let lidos = leitor
        .by_ref()
        .take(LINHA_MAXIMA as u64 + 1)
        .read_line(linha)?;
    if lidos > LINHA_MAXIMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "linha maior que o limite do contrato",
        ));
    }
    Ok(lidos)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn linha_no_limite_passa_e_maior_e_recusada() {
        let mut no_limite = vec![b'a'; LINHA_MAXIMA - 1];
        no_limite.push(b'\n');
        let mut linha = String::new();
        assert_eq!(
            ler_linha(&mut no_limite.as_slice(), &mut linha).unwrap(),
            LINHA_MAXIMA
        );

        let grande = vec![b'a'; LINHA_MAXIMA * 3];
        let mut linha = String::new();
        let falha = ler_linha(&mut grande.as_slice(), &mut linha).unwrap_err();
        assert_eq!(falha.kind(), io::ErrorKind::InvalidData);
        assert!(linha.len() <= LINHA_MAXIMA + 1);
    }
}
