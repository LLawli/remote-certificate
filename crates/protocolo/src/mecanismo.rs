use serde::{Deserialize, Serialize};

/// Um mecanismo de assinatura, pelo nome que ele tem no PKCS#11.
///
/// O driver declara os mecanismos de cada chave e o cliente expõe só esses: um
/// token que não assina RSA-PSS não aparece como capaz de TLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mecanismo {
    /// RSA PKCS#1 v1.5 sobre um DigestInfo já montado por quem chama. É o que
    /// o TLS 1.2 usa na autenticação do cliente.
    #[serde(rename = "CKM_RSA_PKCS")]
    RsaPkcs,
    #[serde(rename = "CKM_SHA256_RSA_PKCS")]
    Sha256RsaPkcs,
    #[serde(rename = "CKM_SHA384_RSA_PKCS")]
    Sha384RsaPkcs,
    #[serde(rename = "CKM_SHA512_RSA_PKCS")]
    Sha512RsaPkcs,
    /// RSA-PSS sobre um hash já calculado.
    #[serde(rename = "CKM_RSA_PKCS_PSS")]
    RsaPkcsPss,
    /// ECDSA sobre um hash já calculado.
    #[serde(rename = "CKM_ECDSA")]
    Ecdsa,
    /// Um mecanismo que esta versão não conhece, declarado por um driver mais
    /// novo. Fica de fora do que o cliente expõe.
    #[serde(other)]
    Desconhecido,
}

/// O TLS 1.3 só aceita RSA-PSS ou ECDSA na assinatura do cliente.
pub fn suporta_tls13(mecanismos: &[Mecanismo]) -> bool {
    mecanismos
        .iter()
        .any(|m| matches!(m, Mecanismo::RsaPkcsPss | Mecanismo::Ecdsa))
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn so_pkcs1_v15_nao_serve_para_tls13() {
        assert!(!suporta_tls13(&[
            Mecanismo::RsaPkcs,
            Mecanismo::Sha256RsaPkcs
        ]));
        assert!(suporta_tls13(&[Mecanismo::RsaPkcs, Mecanismo::RsaPkcsPss]));
        assert!(suporta_tls13(&[Mecanismo::Ecdsa]));
    }

    #[test]
    fn nome_do_pkcs11_no_json() {
        let json = serde_json::to_string(&Mecanismo::Sha256RsaPkcs).unwrap();
        assert_eq!(json, r#""CKM_SHA256_RSA_PKCS""#);
    }

    #[test]
    fn mecanismo_novo_nao_quebra_a_listagem() {
        let lidos: Vec<Mecanismo> =
            serde_json::from_str(r#"["CKM_RSA_PKCS", "CKM_EDDSA"]"#).unwrap();
        assert_eq!(lidos, [Mecanismo::RsaPkcs, Mecanismo::Desconhecido]);
    }
}
