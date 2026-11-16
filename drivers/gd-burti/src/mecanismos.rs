//! Os mecanismos do contrato e como cada um vira uma chamada do PKCS#11.

use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use protocolo::{Erro, Mecanismo, TipoDeErro};

use crate::erro::erro;

/// O algoritmo da chave, lido do certificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoDeChave {
    Rsa,
    Ec,
}

/// Os mecanismos do contrato que uma chave desse tipo pode ter, com o nome
/// deles no PKCS#11. O que o driver declara é a interseção disto com o que o
/// token diz que assina.
pub fn candidatos(tipo: TipoDeChave) -> &'static [(Mecanismo, MechanismType)] {
    match tipo {
        TipoDeChave::Rsa => &[
            (Mecanismo::RsaPkcs, MechanismType::RSA_PKCS),
            (Mecanismo::Sha256RsaPkcs, MechanismType::SHA256_RSA_PKCS),
            (Mecanismo::Sha384RsaPkcs, MechanismType::SHA384_RSA_PKCS),
            (Mecanismo::Sha512RsaPkcs, MechanismType::SHA512_RSA_PKCS),
            (Mecanismo::RsaPkcsPss, MechanismType::RSA_PKCS_PSS),
        ],
        TipoDeChave::Ec => &[(Mecanismo::Ecdsa, MechanismType::ECDSA)],
    }
}

/// A chamada do PKCS#11 para assinar `tamanho` bytes com `mecanismo`.
///
/// O contrato manda o hash pronto no RSA-PSS sem dizer os parâmetros. O driver
/// deduz o hash pelo tamanho e usa o que o TLS 1.3 exige: MGF1 com o mesmo
/// hash e sal do tamanho do hash.
pub fn chamada(mecanismo: Mecanismo, tamanho: usize) -> Result<Mechanism<'static>, Erro> {
    let vazio = || erro(TipoDeErro::PedidoInvalido, "Não há dados para assinar");
    Ok(match mecanismo {
        Mecanismo::RsaPkcs if tamanho == 0 => return Err(vazio()),
        Mecanismo::RsaPkcs => Mechanism::RsaPkcs,
        Mecanismo::Sha256RsaPkcs => Mechanism::Sha256RsaPkcs,
        Mecanismo::Sha384RsaPkcs => Mechanism::Sha384RsaPkcs,
        Mecanismo::Sha512RsaPkcs => Mechanism::Sha512RsaPkcs,
        Mecanismo::RsaPkcsPss => {
            let (hash_alg, mgf) = match tamanho {
                32 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
                48 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
                64 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512),
                _ => {
                    return Err(erro(
                        TipoDeErro::PedidoInvalido,
                        format!(
                            "RSA-PSS recebe um hash SHA-256, SHA-384 ou SHA-512, não {tamanho} bytes"
                        ),
                    ));
                }
            };
            Mechanism::RsaPkcsPss(PkcsPssParams {
                hash_alg,
                mgf,
                s_len: (tamanho as u64).into(),
            })
        }
        Mecanismo::Ecdsa if tamanho == 0 => return Err(vazio()),
        Mecanismo::Ecdsa => Mechanism::Ecdsa,
        Mecanismo::Desconhecido => {
            return Err(erro(
                TipoDeErro::MecanismoNaoSuportado,
                "Mecanismo desconhecido",
            ));
        }
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn chave_ec_so_tem_ecdsa() {
        let ec: Vec<_> = candidatos(TipoDeChave::Ec).iter().map(|c| c.0).collect();
        assert_eq!(ec, [Mecanismo::Ecdsa]);
        assert!(
            !candidatos(TipoDeChave::Rsa)
                .iter()
                .any(|c| c.0 == Mecanismo::Ecdsa)
        );
    }

    #[test]
    fn pss_deduz_o_hash_pelo_tamanho() {
        for (tamanho, hash) in [
            (32, MechanismType::SHA256),
            (48, MechanismType::SHA384),
            (64, MechanismType::SHA512),
        ] {
            match chamada(Mecanismo::RsaPkcsPss, tamanho).unwrap() {
                Mechanism::RsaPkcsPss(p) => {
                    assert_eq!(p.hash_alg, hash);
                    assert_eq!(u64::from(p.s_len), tamanho as u64);
                }
                outro => panic!("{outro:?}"),
            }
        }
        let falha = chamada(Mecanismo::RsaPkcsPss, 20).unwrap_err();
        assert_eq!(falha.tipo, TipoDeErro::PedidoInvalido);
    }

    #[test]
    fn mecanismo_desconhecido_nao_e_suportado() {
        let falha = chamada(Mecanismo::Desconhecido, 32).unwrap_err();
        assert_eq!(falha.tipo, TipoDeErro::MecanismoNaoSuportado);
    }
}
