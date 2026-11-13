//! Do contrato do remote-certificate para o `remoteid servir` e de volta.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use protocolo::{
    Apresentacao, Campo, Chave, Erro, Fator, Mecanismo, PedidoDeFatores, Segredo, TipoDeErro,
    TipoDeFator, VERSAO,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// O HSM da Certisign só assina RSA PKCS#1 v1.5: nada de PSS, nada de TLS 1.3.
pub const MECANISMOS: [Mecanismo; 4] = [
    Mecanismo::RsaPkcs,
    Mecanismo::Sha256RsaPkcs,
    Mecanismo::Sha384RsaPkcs,
    Mecanismo::Sha512RsaPkcs,
];

// O começo do DigestInfo (RFC 8017, 9.2) de cada resumo, antes dos bytes dele.
const DIGEST_INFO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// As regras de recusa do `servir` (o fragmento em `regra=`) que dizem que o
/// servidor recusou a senha, o PIN ou o OTP.
const RECUSAS: [&str; 4] = [
    "regra=pin ou e-token incorreto",
    "regra=senha inv",
    "regra=usuariosenhainvalido",
    "regra=não existe autorização válida",
];

pub fn apresentacao() -> Apresentacao {
    let fator = |nome: &str, tipo, rotulo: &str| Fator {
        nome: nome.into(),
        tipo,
        rotulo: rotulo.into(),
    };
    Apresentacao {
        driver: "remoteid".into(),
        versao: env!("CARGO_PKG_VERSION").into(),
        protocolo: VERSAO,
        fatores: vec![
            // O PIN local que cifra a senha no disco do servidor. O driver o
            // gera no `configurar`; ninguém o digita.
            fator("pin", TipoDeFator::Guardado, "PIN local do RemoteID"),
            fator("senha", TipoDeFator::Guardado, "Senha da conta RemoteID"),
            fator("otp", TipoDeFator::DaPessoa, "Código do autenticador"),
        ],
        configuracao: vec![
            Campo {
                nome: "email".into(),
                rotulo: "E-mail da conta RemoteID".into(),
                secreto: false,
            },
            Campo {
                nome: "senha".into(),
                rotulo: "Senha da conta RemoteID".into(),
                secreto: true,
            },
        ],
    }
}

/// O que vai no `assinar` do `servir`, sempre no formato `cru`.
#[derive(Debug, PartialEq, Eq)]
pub enum Entrada {
    /// O SHA-256 em hexadecimal, o caminho que o aplicativo oficial usa.
    Hash(String),
    /// Um DigestInfo pronto (ou o bloco que o chamador montou).
    DigestInfo(Vec<u8>),
}

pub fn entrada(mecanismo: Mecanismo, dados: &[u8]) -> Result<Entrada, Erro> {
    let com_prefixo = |prefixo: &[u8], resumo: &[u8]| [prefixo, resumo].concat();
    match mecanismo {
        Mecanismo::RsaPkcs => Ok(Entrada::DigestInfo(dados.to_vec())),
        Mecanismo::Sha256RsaPkcs => Ok(Entrada::Hash(hex(&Sha256::digest(dados)))),
        Mecanismo::Sha384RsaPkcs => Ok(Entrada::DigestInfo(com_prefixo(
            &DIGEST_INFO_SHA384,
            &Sha384::digest(dados),
        ))),
        Mecanismo::Sha512RsaPkcs => Ok(Entrada::DigestInfo(com_prefixo(
            &DIGEST_INFO_SHA512,
            &Sha512::digest(dados),
        ))),
        outro => Err(Erro {
            tipo: TipoDeErro::MecanismoNaoSuportado,
            mensagem: format!("o RemoteID não assina com {outro:?}"),
        }),
    }
}

/// O pedido de `assinar` para o `servir`.
pub fn assinar(id: u64, chave: &str, entrada: Entrada) -> Value {
    let mut pedido = json!({"id": id, "op": "assinar", "formato": "cru", "certificado": chave});
    match entrada {
        Entrada::Hash(hash) => pedido["hash"] = json!(hash),
        Entrada::DigestInfo(bloco) => pedido["digest_info"] = json!(STANDARD.encode(bloco)),
    }
    pedido
}

/// Um erro do `servir` no vocabulário do contrato.
pub fn erro(tipo: &str, mensagem: &str) -> Erro {
    let tipo = match tipo {
        "cancelado" => TipoDeErro::Cancelado,
        "pin_bloqueado" => TipoDeErro::Bloqueado,
        "rede" => TipoDeErro::Rede,
        "pedido_invalido" | "bloco_invalido" => TipoDeErro::PedidoInvalido,
        t if t.starts_with("nao_preparado") => TipoDeErro::NaoConfigurado,
        t if t.starts_with("servidor") && RECUSAS.iter().any(|r| t.contains(r)) => {
            TipoDeErro::FatorRecusado
        }
        _ => TipoDeErro::Outro,
    };
    Erro {
        tipo,
        mensagem: mensagem.to_string(),
    }
}

/// O `pedir` do `servir` como um pedido de fatores do contrato. A senha só é
/// pedida quando não está guardada no estado do `servir`: com ela guardada,
/// omiti-la mantém a que está lá.
pub fn pedido(pedir: &Value) -> PedidoDeFatores {
    let sim = |campo: &str| pedir[campo].as_bool().unwrap_or(false);
    let mut fatores = Vec::new();
    if sim("pedir_pin") {
        fatores.push("pin".to_string());
    }
    if sim("pedir_senha") && !sim("senha_guardada") {
        fatores.push("senha".to_string());
    }
    fatores.push("otp".to_string());
    PedidoDeFatores {
        fatores,
        recusa: pedir["recusa"].as_str().map(str::to_string),
    }
}

/// Os fatores para o `servir`, só os que ele conhece.
pub fn fatores(id: u64, fatores: &BTreeMap<String, Segredo>) -> Value {
    let mut saida = serde_json::Map::new();
    for nome in ["otp", "pin", "senha"] {
        if let Some(valor) = fatores.get(nome) {
            saida.insert(nome.into(), json!(valor.expor()));
        }
    }
    json!({"id": id, "fatores": saida})
}

/// As chaves da visão do `servir`. Um certificado sem DER na carteira fica de
/// fora: sem ele não há o que expor.
pub fn chaves(visao: &Value) -> Result<Vec<Chave>, Erro> {
    if visao["preparado"] != json!(true) {
        return Err(Erro {
            tipo: TipoDeErro::NaoConfigurado,
            mensagem: "a conta RemoteID não foi configurada".into(),
        });
    }
    let certificados = visao["certificados"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(certificados
        .iter()
        .filter_map(|c| {
            let der = STANDARD.decode(c["certificado"].as_str()?).ok()?;
            Some(Chave {
                id: c["chave"].as_str()?.to_string(),
                rotulo: c["titular"].as_str().unwrap_or_default().to_string(),
                certificado: der,
                mecanismos: MECANISMOS.to_vec(),
            })
        })
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn sha256_vai_como_hash_e_os_outros_como_digest_info() {
        let vazio_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            entrada(Mecanismo::Sha256RsaPkcs, b"").unwrap(),
            Entrada::Hash(vazio_sha256.into())
        );

        let Entrada::DigestInfo(bloco) = entrada(Mecanismo::Sha384RsaPkcs, b"").unwrap() else {
            panic!("SHA-384 vai como DigestInfo");
        };
        assert_eq!(bloco.len(), 19 + 48);
        assert_eq!(&bloco[19..], Sha384::digest(b"").as_slice());

        let Entrada::DigestInfo(bloco) = entrada(Mecanismo::Sha512RsaPkcs, b"").unwrap() else {
            panic!("SHA-512 vai como DigestInfo");
        };
        assert_eq!(bloco.len(), 19 + 64);
        // O comprimento declarado na SEQUENCE é o resto do bloco.
        assert_eq!(bloco[1] as usize, bloco.len() - 2);
    }

    #[test]
    fn rsa_pkcs_assina_o_bloco_como_veio() {
        assert_eq!(
            entrada(Mecanismo::RsaPkcs, &[1, 2, 3]).unwrap(),
            Entrada::DigestInfo(vec![1, 2, 3])
        );
    }

    #[test]
    fn sem_pss_nem_ecdsa() {
        for mecanismo in [Mecanismo::RsaPkcsPss, Mecanismo::Ecdsa] {
            let erro = entrada(mecanismo, b"x").unwrap_err();
            assert_eq!(erro.tipo, TipoDeErro::MecanismoNaoSuportado);
        }
        assert!(!protocolo::suporta_tls13(&MECANISMOS));
    }

    #[test]
    fn recusa_do_servidor_vira_fator_recusado() {
        let recusa = "servidor http=200 regra=pin ou e-token incorreto";
        assert_eq!(erro(recusa, "").tipo, TipoDeErro::FatorRecusado);
        let senha = "servidor http=500 regra=usuariosenhainvalido";
        assert_eq!(erro(senha, "").tipo, TipoDeErro::FatorRecusado);
        let outra = "servidor http=500 regra=sem regra";
        assert_eq!(erro(outra, "").tipo, TipoDeErro::Outro);
        assert_eq!(
            erro("nao_preparado: sem conta", "").tipo,
            TipoDeErro::NaoConfigurado
        );
    }

    #[test]
    fn senha_guardada_no_servir_nao_e_pedida() {
        let p = pedido(&json!({"pedir_pin": true, "pedir_senha": true,
                                "senha_guardada": true, "recusa": "x"}));
        assert_eq!(p.fatores, ["pin", "otp"]);
        assert_eq!(p.recusa.as_deref(), Some("x"));

        let p = pedido(&json!({"pedir_pin": false, "pedir_senha": true,
                                "senha_guardada": false, "recusa": null}));
        assert_eq!(p.fatores, ["senha", "otp"]);
    }

    #[test]
    fn so_fatores_conhecidos_vao_ao_servir() {
        let enviados = BTreeMap::from([
            ("otp".to_string(), Segredo::novo("123456".into())),
            ("outro".to_string(), Segredo::novo("x".into())),
        ]);
        assert_eq!(
            fatores(7, &enviados),
            json!({"id": 7, "fatores": {"otp": "123456"}})
        );
    }
}
