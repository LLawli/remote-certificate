//! O servidor com o driver RemoteID, o `remoteid servir` e o servidor falso do
//! RemoteID-linux: cada tipo de assinatura de ponta a ponta, conferida contra a
//! chave pública do certificado que o token expõe.
//!
//! Precisa de `REMOTEID_BIN` e `REMOTEID_MOCK_BIN`: `eval "$(scripts/remoteid.sh)"`.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use protocolo::{Chave, Fator, Mecanismo, Segredo, TipoDeErro};
use rsa::PublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use servidor::driver::{Conversa, Driver, Falha};
use servidor::fatores::{Motivo, Pessoa};
use servidor::token::{FalhaDoToken, Token};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

const EMAIL: &str = "teste@remoteid.local";
const SENHA: &str = "teste-1234";
const OTP: &str = "123456";
const DOCUMENTO: &[u8] = b"procuracao de teste";

fn binario(variavel: &str) -> PathBuf {
    std::env::var_os(variavel)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("falta {variavel}: rode eval \"$(scripts/remoteid.sh)\""))
}

/// O servidor falso do RemoteID, morto quando o teste acaba.
struct Mock {
    processo: Child,
    url: String,
}

impl Mock {
    fn subir() -> Mock {
        let mut processo = Command::new(binario("REMOTEID_MOCK_BIN"))
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut url = String::new();
        BufReader::new(processo.stdout.take().unwrap())
            .read_line(&mut url)
            .unwrap();
        Mock {
            processo,
            url: url.trim().to_string(),
        }
    }

    /// Esquece as sessões, como o servidor real faz quando elas vencem.
    fn expirar_sessoes(&self) {
        ureq::post(format!("{}/_mock/expirar", self.url))
            .send_empty()
            .unwrap();
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}

/// Um diretório só deste teste, no target (fora do tmpfs).
fn diretorio(nome: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("remoteid-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// O driver como o servidor o lança, com o stderr num arquivo para conferir.
fn lancar(dir: &Path, mock: &Mock) -> Driver {
    let estado = dir.join("estado");
    std::fs::create_dir_all(&estado).unwrap();
    let stderr = File::create(dir.join("stderr.log")).unwrap();
    Driver::lancar(
        Command::new(env!("CARGO_BIN_EXE_remote-certificate-driver-remoteid"))
            .arg("--estado")
            .arg(&estado)
            .arg("--remoteid")
            .arg(binario("REMOTEID_BIN"))
            .arg("--servidor")
            .arg(&mock.url)
            .stderr(stderr),
    )
    .expect("o driver sobe e se apresenta")
}

fn valores(email: &str, senha: &str) -> BTreeMap<String, Segredo> {
    BTreeMap::from([
        ("email".to_string(), Segredo::novo(email.into())),
        ("senha".to_string(), Segredo::novo(senha.into())),
    ])
}

fn configurado(dir: &Path, mock: &Mock) -> Token {
    let mut token = Token::novo(lancar(dir, mock), BTreeMap::new());
    token.configurar(valores(EMAIL, SENHA)).expect("configura");
    token
}

/// Quem pediu a assinatura: responde os códigos na ordem e anota as perguntas.
struct Digita {
    codigos: VecDeque<&'static str>,
    perguntas: Vec<(Vec<String>, Option<String>)>,
}

impl Digita {
    fn codigos(codigos: &[&'static str]) -> Digita {
        Digita {
            codigos: codigos.iter().copied().collect(),
            perguntas: Vec::new(),
        }
    }
}

impl Pessoa for Digita {
    fn pedir(
        &mut self,
        fatores: &[&Fator],
        recusa: Option<&str>,
    ) -> Option<BTreeMap<String, Segredo>> {
        self.perguntas.push((
            fatores.iter().map(|f| f.nome.clone()).collect(),
            recusa.map(str::to_string),
        ));
        let codigo = self.codigos.pop_front()?;
        Some(BTreeMap::from([(
            "otp".to_string(),
            Segredo::novo(codigo.into()),
        )]))
    }
}

fn chave_publica(chave: &Chave) -> PublicKey {
    let certificado = Certificate::from_der(&chave.certificado).expect("X.509 em DER");
    let spki = certificado
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    PublicKey::from_public_key_der(&spki).expect("chave RSA")
}

fn digest_info(prefixo: &[u8], resumo: &[u8]) -> Vec<u8> {
    [prefixo, resumo].concat()
}

const PREFIXO_SHA1: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const PREFIXO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const PREFIXO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const PREFIXO_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

#[test]
fn configura_e_expoe_o_certificado_com_os_mecanismos_do_remoteid() {
    let mock = Mock::subir();
    let dir = diretorio("lista");
    let mut token = configurado(&dir, &mock);

    let apresentacao = token.driver().apresentacao().clone();
    assert_eq!(apresentacao.driver, "remoteid");

    let chaves = token.listar().unwrap();
    assert_eq!(chaves.len(), 1);
    let chave = &chaves[0];
    assert!(chave.rotulo.contains("TESTE DESKTOPID"), "{}", chave.rotulo);
    chave_publica(chave);
    assert_eq!(
        chave.mecanismos,
        [
            Mecanismo::RsaPkcs,
            Mecanismo::Sha256RsaPkcs,
            Mecanismo::Sha384RsaPkcs,
            Mecanismo::Sha512RsaPkcs
        ]
    );
    assert!(!protocolo::suporta_tls13(&chave.mecanismos));
}

#[test]
fn cada_tipo_de_assinatura_confere_com_o_certificado() {
    let mock = Mock::subir();
    let dir = diretorio("tipos");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    let publica = chave_publica(&chave);
    let mut pessoa = Digita::codigos(&[OTP]);

    // Os mecanismos com o resumo calculado pelo driver.
    let casos: [(Mecanismo, Pkcs1v15Sign, Vec<u8>); 3] = [
        (
            Mecanismo::Sha256RsaPkcs,
            Pkcs1v15Sign::new::<Sha256>(),
            Sha256::digest(DOCUMENTO).to_vec(),
        ),
        (
            Mecanismo::Sha384RsaPkcs,
            Pkcs1v15Sign::new::<Sha384>(),
            Sha384::digest(DOCUMENTO).to_vec(),
        ),
        (
            Mecanismo::Sha512RsaPkcs,
            Pkcs1v15Sign::new::<Sha512>(),
            Sha512::digest(DOCUMENTO).to_vec(),
        ),
    ];
    for (mecanismo, esquema, resumo) in casos {
        let assinatura = token
            .assinar(&chave.id, mecanismo, DOCUMENTO, &mut pessoa)
            .unwrap_or_else(|e| panic!("{mecanismo:?}: {e}"));
        publica
            .verify(esquema, &resumo, &assinatura)
            .unwrap_or_else(|e| panic!("{mecanismo:?} não confere: {e}"));
    }

    // CKM_RSA_PKCS assina o bloco que o chamador montou: os DigestInfo que o
    // TLS 1.2 e os assinadores pedem, e o MD5+SHA-1 cru do TLS 1.0.
    let blocos = [
        digest_info(&PREFIXO_SHA1, &Sha1::digest(DOCUMENTO)),
        digest_info(&PREFIXO_SHA256, &Sha256::digest(DOCUMENTO)),
        digest_info(&PREFIXO_SHA384, &Sha384::digest(DOCUMENTO)),
        digest_info(&PREFIXO_SHA512, &Sha512::digest(DOCUMENTO)),
        [vec![0x11; 16], Sha1::digest(DOCUMENTO).to_vec()].concat(),
    ];
    for bloco in blocos {
        let assinatura = token
            .assinar(&chave.id, Mecanismo::RsaPkcs, &bloco, &mut pessoa)
            .unwrap_or_else(|e| panic!("bloco de {} bytes: {e}", bloco.len()));
        publica
            .verify(Pkcs1v15Sign::new_unprefixed(), &bloco, &assinatura)
            .unwrap_or_else(|e| panic!("bloco de {} bytes não confere: {e}", bloco.len()));
    }

    // Uma pergunta só: o PIN local veio do cofre, e a sessão aberta pelo
    // primeiro OTP atendeu as outras assinaturas.
    assert_eq!(pessoa.perguntas, [(vec!["otp".to_string()], None)]);
}

#[test]
fn otp_errado_volta_a_pessoa_com_a_recusa() {
    let mock = Mock::subir();
    let dir = diretorio("otp-errado");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    let mut pessoa = Digita::codigos(&["999999", OTP]);

    token
        .assinar(&chave.id, Mecanismo::Sha256RsaPkcs, DOCUMENTO, &mut pessoa)
        .expect("o segundo código assina");
    assert_eq!(pessoa.perguntas.len(), 2);
    assert_eq!(pessoa.perguntas[0].1, None);
    assert!(
        pessoa.perguntas[1].1.is_some(),
        "a segunda pergunta traz a recusa"
    );
}

#[test]
fn pessoa_que_desiste_cancela_a_assinatura() {
    let mock = Mock::subir();
    let dir = diretorio("desiste");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    let mut pessoa = Digita::codigos(&[]);

    let falha = token.assinar(&chave.id, Mecanismo::Sha256RsaPkcs, DOCUMENTO, &mut pessoa);
    assert!(
        matches!(falha, Err(FalhaDoToken::Cancelado(Motivo::PessoaDesistiu))),
        "{falha:?}"
    );

    // O token continua servindo depois da desistência.
    let mut pessoa = Digita::codigos(&[OTP]);
    token
        .assinar(&chave.id, Mecanismo::Sha256RsaPkcs, DOCUMENTO, &mut pessoa)
        .expect("assina depois");
}

#[test]
fn sessao_vencida_pede_o_codigo_de_novo() {
    let mock = Mock::subir();
    let dir = diretorio("sessao");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    let mut pessoa = Digita::codigos(&[OTP, OTP]);

    token
        .assinar(&chave.id, Mecanismo::Sha256RsaPkcs, DOCUMENTO, &mut pessoa)
        .unwrap();
    mock.expirar_sessoes();
    token
        .assinar(&chave.id, Mecanismo::Sha256RsaPkcs, DOCUMENTO, &mut pessoa)
        .unwrap();
    assert_eq!(pessoa.perguntas.len(), 2);
}

#[test]
fn mecanismo_sem_suporte_nao_gasta_o_codigo() {
    let mock = Mock::subir();
    let dir = diretorio("pss");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    let mut pessoa = Digita::codigos(&[OTP]);

    let falha = token.assinar(&chave.id, Mecanismo::RsaPkcsPss, &[0; 32], &mut pessoa);
    assert!(
        matches!(
            &falha,
            Err(FalhaDoToken::Driver(Falha::Driver(e))) if e.tipo == TipoDeErro::MecanismoNaoSuportado
        ),
        "{falha:?}"
    );
    assert!(pessoa.perguntas.is_empty());
}

#[test]
fn senha_errada_na_configuracao_e_recusada() {
    let mock = Mock::subir();
    let dir = diretorio("senha-errada");
    let mut token = Token::novo(lancar(&dir, &mock), BTreeMap::new());

    let falha = token.configurar(valores(EMAIL, "outra-senha"));
    assert!(
        matches!(
            &falha,
            Err(FalhaDoToken::Driver(Falha::Driver(e))) if e.tipo == TipoDeErro::FatorRecusado
        ),
        "{falha:?}"
    );
}

#[test]
fn sem_configurar_nao_ha_chaves() {
    let mock = Mock::subir();
    let dir = diretorio("sem-conta");
    let mut token = Token::novo(lancar(&dir, &mock), BTreeMap::new());

    let falha = token.listar();
    assert!(
        matches!(
            &falha,
            Err(FalhaDoToken::Driver(Falha::Driver(e))) if e.tipo == TipoDeErro::NaoConfigurado
        ),
        "{falha:?}"
    );
}

#[test]
fn nenhum_segredo_em_claro_no_disco_nem_no_log() {
    let mock = Mock::subir();
    let dir = diretorio("segredos");
    let mut token = configurado(&dir, &mock);
    let chave = token.listar().unwrap().remove(0);
    token
        .assinar(
            &chave.id,
            Mecanismo::Sha256RsaPkcs,
            DOCUMENTO,
            &mut Digita::codigos(&[OTP]),
        )
        .unwrap();
    drop(token);

    let mut tudo = Vec::new();
    let mut pendentes = vec![dir.clone()];
    while let Some(caminho) = pendentes.pop() {
        for entrada in std::fs::read_dir(&caminho).unwrap() {
            let entrada = entrada.unwrap().path();
            if entrada.is_dir() {
                pendentes.push(entrada);
            } else {
                tudo.extend(std::fs::read(&entrada).unwrap());
            }
        }
    }
    let tudo = String::from_utf8_lossy(&tudo);
    for segredo in [SENHA, OTP, "procuracao de teste"] {
        assert!(!tudo.contains(segredo), "{segredo} em claro no disco");
    }
}
