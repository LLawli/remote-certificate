//! O que os testes de integração do driver RemoteID compartilham: o servidor
//! falso do RemoteID, o banco do servidor, o token configurado e a janela do
//! OTP que responde sozinha.

// Cada arquivo de teste usa uma parte.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use protocolo::{Chave, Segredo};
use rsa::PublicKey;
use rsa::pkcs8::DecodePublicKey;
use servidor::banco::{Banco, ChaveDoBanco, IdDoToken, ler_chave, travar};
use servidor::driver::Driver;
use servidor::lancador::Lancador;
use servidor::token::{GuardaNoBanco, Token};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

pub const EMAIL: &str = "teste@remoteid.local";

pub const SENHA: &str = "teste-1234";

pub const OTP: &str = "123456";

pub const PIN_PESSOAL: &str = "pessoal-2468";

pub const DOCUMENTO: &[u8] = b"procuracao de teste";

pub fn binario(variavel: &str) -> PathBuf {
    std::env::var_os(variavel)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("falta {variavel}: rode eval \"$(scripts/remoteid.sh)\""))
}

/// O servidor falso do RemoteID, morto quando o teste acaba.
pub struct Mock {
    processo: Child,
    pub url: String,
}

impl Mock {
    pub fn subir() -> Mock {
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
    pub fn expirar_sessoes(&self) {
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
pub fn diretorio(nome: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("remoteid-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn valores(email: &str, senha: &str) -> BTreeMap<String, Segredo> {
    BTreeMap::from([
        ("email".to_string(), Segredo::novo(email.into())),
        ("senha".to_string(), Segredo::novo(senha.into())),
    ])
}

/// O banco do servidor no diretório do teste, com a chave num arquivo como o
/// secret do Docker. Abrir de novo é o servidor reiniciando.
pub fn banco(dir: &Path) -> Arc<Mutex<Banco>> {
    let arquivo = dir.join("chave");
    if !arquivo.exists() {
        let chave = ChaveDoBanco::aleatorio().unwrap();
        std::fs::write(&arquivo, chave.expor()).unwrap();
    }
    let banco = Banco::abrir(&dir.join("banco.db"), ler_chave(&arquivo).unwrap()).unwrap();
    Arc::new(Mutex::new(banco))
}

pub fn chave_publica(chave: &Chave) -> PublicKey {
    let certificado = Certificate::from_der(&chave.certificado).expect("X.509 em DER");
    let spki = certificado
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    PublicKey::from_public_key_der(&spki).expect("chave RSA")
}

/// Como o serviço do teste sobe os drivers: sem isolar (o driver está num
/// caminho absoluto, e a pasta dos drivers não conta), com o estado dos tokens
/// no diretório do teste.
pub fn lancador(dir: &Path) -> Lancador {
    Lancador::novo("/", dir.join("estados"))
}

/// O token configurado no banco como o administrador faria: o driver com os
/// argumentos dele, e a conta pelo `configurar`.
pub fn token_no_banco(dir: &Path, mock: &Mock, banco: &Arc<Mutex<Banco>>) -> IdDoToken {
    let estado = dir.join("estado");
    std::fs::create_dir_all(&estado).unwrap();
    let argumentos: Vec<String> = [
        "--estado".into(),
        estado.display().to_string(),
        "--remoteid".into(),
        binario("REMOTEID_BIN").display().to_string(),
        "--servidor".into(),
        mock.url.clone(),
    ]
    .into();
    let executavel = env!("CARGO_BIN_EXE_remote-certificate-driver-remoteid");
    let id = travar(banco)
        .criar_token("RemoteID", executavel, &argumentos)
        .unwrap();
    configurar_por_fora(banco, id);
    id
}

/// O que `remote-certificate token configurar` faz: outro processo do driver,
/// com o serviço rodando ou não.
pub fn configurar_por_fora(banco: &Arc<Mutex<Banco>>, id: IdDoToken) {
    let registro = travar(banco)
        .tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap();
    let driver = Driver::lancar(Command::new(&registro.driver).args(&registro.argumentos)).unwrap();
    Token::abrir(driver, GuardaNoBanco::novo(banco.clone(), id))
        .unwrap()
        .configurar(valores(EMAIL, SENHA))
        .unwrap();
}

pub fn otp_da_api(codigo: &str) -> BTreeMap<String, Segredo> {
    BTreeMap::from([("otp".to_string(), Segredo::novo(codigo.into()))])
}

/// A janela do OTP no teste: responde os códigos na ordem e guarda as
/// perguntas. Sem código, fecha a janela. Com `demora`, é a pessoa lenta.
#[derive(Default)]
pub struct JanelaDeTeste {
    pub codigos: Mutex<VecDeque<&'static str>>,
    pub perguntas: Mutex<Vec<agente::dialogo::Pergunta>>,
    pub demora: Mutex<std::time::Duration>,
}

impl agente::dialogo::Dialogo for JanelaDeTeste {
    fn perguntar(&self, pergunta: &agente::dialogo::Pergunta) -> Option<BTreeMap<String, Segredo>> {
        self.perguntas.lock().unwrap().push(pergunta.clone());
        std::thread::sleep(*self.demora.lock().unwrap());
        let codigo = self.codigos.lock().unwrap().pop_front()?;
        Some(otp_da_api(codigo))
    }
}
