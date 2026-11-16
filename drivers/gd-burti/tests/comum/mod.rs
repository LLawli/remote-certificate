//! O que os testes de integração dividem: o driver num processo, conversado
//! pelo contrato como o servidor faria, e a conferência das assinaturas contra
//! a chave pública do certificado.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde_json::{Value, json};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Um diretório de trabalho só do teste, no `target/` (no disco de dados, não
/// no tmpfs).
pub fn diretorio(nome: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("gd-burti")
        .join(format!("{nome}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// O driver rodando, com o stdin e o stdout na mão do teste.
pub struct Driver {
    filho: Child,
    entrada: ChildStdin,
    saida: BufReader<ChildStdout>,
    proximo: u64,
}

impl Driver {
    /// Sobe o driver com o módulo dado, no diretório de estado `estado`.
    pub fn subir(modulo: &Path, estado: &Path, ambiente: &[(&str, &str)]) -> Self {
        let mut comando = Command::new(env!("CARGO_BIN_EXE_remote-certificate-driver-gd-burti"));
        comando
            .arg("--modulo")
            .arg(modulo)
            .current_dir(estado)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (nome, valor) in ambiente {
            comando.env(nome, valor);
        }
        let mut filho = comando.spawn().expect("o driver não subiu");
        let entrada = filho.stdin.take().unwrap();
        let saida = BufReader::new(filho.stdout.take().unwrap());
        Self {
            filho,
            entrada,
            saida,
            proximo: 1,
        }
    }

    pub fn mandar(&mut self, mensagem: &Value) {
        writeln!(self.entrada, "{mensagem}").unwrap();
        self.entrada.flush().unwrap();
    }

    pub fn receber(&mut self) -> Value {
        let mut linha = String::new();
        let lidos = self.saida.read_line(&mut linha).unwrap();
        assert!(lidos > 0, "o driver fechou o stdout");
        serde_json::from_str(&linha).unwrap_or_else(|e| panic!("{e}: {linha}"))
    }

    /// Manda uma operação com um `id` novo e devolve a primeira resposta.
    pub fn pedir(&mut self, mut operacao: Value) -> Value {
        let id = self.proximo;
        self.proximo += 1;
        operacao["id"] = json!(id);
        self.mandar(&operacao);
        let resposta = self.receber();
        assert_eq!(resposta["id"], id, "{resposta}");
        resposta
    }

    pub fn apresentar(&mut self) -> Value {
        let resposta = self.pedir(json!({"op": "apresentar", "versao": protocolo::VERSAO}));
        resposta["ok"].clone()
    }

    pub fn configurar(&mut self, serie: &str, pin: &str) -> Value {
        self.pedir(json!({"op": "configurar", "valores": {"serie": serie, "pin": pin}}))
    }

    pub fn listar(&mut self) -> Value {
        self.pedir(json!({"op": "listar"}))
    }

    /// Assina respondendo `pin` ao pedido de fatores, como o servidor faria
    /// com o fator guardado. Devolve a resposta final.
    pub fn assinar(&mut self, chave: &str, mecanismo: &str, dados: &[u8], pin: &str) -> Value {
        let resposta = self.pedir(json!({
            "op": "assinar", "chave": chave, "mecanismo": mecanismo,
            "dados": STANDARD.encode(dados),
        }));
        let Some(pedido) = resposta.get("pedir") else {
            return resposta;
        };
        assert_eq!(pedido, &json!({"fatores": ["pin"], "recusa": null}));
        let id = resposta["id"].clone();
        self.mandar(&json!({"id": id, "fatores": {"pin": pin}}));
        let final_ = self.receber();
        assert_eq!(final_["id"], id);
        assert!(
            final_.get("pedir").is_none(),
            "pediu o PIN de novo: {final_}"
        );
        final_
    }

    /// Fecha o stdin, espera o driver sair e devolve o stderr dele.
    pub fn encerrar(self) -> String {
        let Driver {
            mut filho,
            entrada,
            saida,
            ..
        } = self;
        drop(entrada);
        drop(saida);
        let estado = filho.wait().unwrap();
        let mut stderr = String::new();
        filho
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(estado.success(), "o driver saiu com {estado}: {stderr}");
        stderr
    }
}

pub fn tipo_do_erro(resposta: &Value) -> &str {
    resposta["erro"]["tipo"]
        .as_str()
        .unwrap_or_else(|| panic!("não é uma falha: {resposta}"))
}

pub fn assinatura(resposta: &Value) -> Vec<u8> {
    let texto = resposta["ok"]["assinatura"]
        .as_str()
        .unwrap_or_else(|| panic!("não assinou: {resposta}"));
    STANDARD.decode(texto).unwrap()
}

/// O prefixo DER do DigestInfo do SHA-256 (RFC 8017, seção 9.2).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Os dados que vão no pedido para assinar `mensagem` com `mecanismo`, como o
/// contrato manda, e o algoritmo do ring que confere o resultado sobre a
/// mensagem.
pub fn dados_e_conferencia(
    mecanismo: &str,
    mensagem: &[u8],
) -> (Vec<u8>, &'static dyn VerificationAlgorithm) {
    let hash = |algoritmo| digest::digest(algoritmo, mensagem).as_ref().to_vec();
    match mecanismo {
        "CKM_RSA_PKCS" => (
            [DIGEST_INFO_SHA256, &hash(&digest::SHA256)].concat(),
            &signature::RSA_PKCS1_2048_8192_SHA256,
        ),
        "CKM_SHA256_RSA_PKCS" => (mensagem.to_vec(), &signature::RSA_PKCS1_2048_8192_SHA256),
        "CKM_SHA384_RSA_PKCS" => (mensagem.to_vec(), &signature::RSA_PKCS1_2048_8192_SHA384),
        "CKM_SHA512_RSA_PKCS" => (mensagem.to_vec(), &signature::RSA_PKCS1_2048_8192_SHA512),
        "CKM_RSA_PKCS_PSS" => (hash(&digest::SHA256), &signature::RSA_PSS_2048_8192_SHA256),
        "CKM_ECDSA" => (hash(&digest::SHA256), &signature::ECDSA_P256_SHA256_FIXED),
        outro => panic!("mecanismo sem conferência no teste: {outro}"),
    }
}

/// Se `assinatura` sobre `mensagem` confere com a chave pública do
/// certificado.
pub fn confere(
    certificado: &[u8],
    algoritmo: &'static dyn VerificationAlgorithm,
    mensagem: &[u8],
    assinatura: &[u8],
) -> bool {
    let (_, certificado) = X509Certificate::from_der(certificado).unwrap();
    let chave = &certificado.public_key().subject_public_key.data;
    UnparsedPublicKey::new(algoritmo, chave.as_ref())
        .verify(mensagem, assinatura)
        .is_ok()
}

/// Assina com cada mecanismo que a chave declarou e confere cada assinatura
/// com o certificado. Devolve os mecanismos assinados.
pub fn assinar_com_cada_mecanismo(driver: &mut Driver, chave: &Value, pin: &str) -> Vec<String> {
    let id = chave["id"].as_str().unwrap();
    let certificado = STANDARD
        .decode(chave["certificado"].as_str().unwrap())
        .unwrap();
    let mut assinados = Vec::new();
    for mecanismo in chave["mecanismos"].as_array().unwrap() {
        let mecanismo = mecanismo.as_str().unwrap();
        let mensagem = format!("documento assinado com {mecanismo}");
        let (dados, algoritmo) = dados_e_conferencia(mecanismo, mensagem.as_bytes());
        let resposta = driver.assinar(id, mecanismo, &dados, pin);
        let mut assinada = assinatura(&resposta);
        assert!(
            confere(&certificado, algoritmo, mensagem.as_bytes(), &assinada),
            "a assinatura com {mecanismo} não confere com o certificado"
        );
        // A conferência pega uma assinatura adulterada.
        assinada[0] ^= 1;
        assert!(!confere(
            &certificado,
            algoritmo,
            mensagem.as_bytes(),
            &assinada
        ));
        assinados.push(mecanismo.to_owned());
    }
    assinados
}
