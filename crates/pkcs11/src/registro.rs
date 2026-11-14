//! O registro das chamadas Cryptoki, para quando um navegador ou assinador
//! falha e a pessoa só sabe dizer "não assinou" (portado do RemoteID-linux).
//!
//! Cada chamada vira uma linha com a função, os argumentos que não são
//! segredo, o `CKR_*` devolvido e a duração. O PIN do `C_Login` e os dados a
//! assinar nunca entram: dos dados, só o tamanho e o começo do SHA-256.
//!
//! As chamadas de rotina (listar slots, ler atributos) ficam num anel em
//! memória e só vão ao disco junto de uma que importa: uma operação, um erro
//! ou um `panic`. Assim um navegador aberto o dia inteiro não enche o disco, e
//! o que falhou leva ao disco as últimas [`CONTEXTO`] chamadas antes.

use std::collections::VecDeque;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Mutex, Once};
use std::time::Instant;

use cryptoki_sys::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::trava;

/// Troca o diretório do registro.
pub const ENV_REGISTRO: &str = "REMOTE_CERTIFICATE_REGISTRO";
const ARQUIVO: &str = "pkcs11.log";
/// Passando disso, o arquivo vira `.1` e começa outro.
const TAMANHO_MAXIMO: u64 = 1024 * 1024;
/// Quantas chamadas de rotina ficam no anel.
const CONTEXTO: usize = 64;
/// Quantos tipos de atributo de um modelo entram na linha.
const ATRIBUTOS: usize = 32;

/// As chamadas que sempre vão ao disco, com o anel antes delas.
const OPERACOES: &[&str] = &[
    "C_Login",
    "C_Logout",
    "C_SignInit",
    "C_Sign",
    "C_SignFinal",
    "C_EncryptInit",
    "C_Encrypt",
];

struct Registro {
    contexto: VecDeque<(u64, Value)>,
    /// As de rotina que saíram do anel sem ir ao disco.
    omitidas: u64,
}

static REGISTRO: Mutex<Registro> = Mutex::new(Registro {
    contexto: VecDeque::new(),
    omitidas: 0,
});

/// A mensagem e o local do último `panic` dentro de uma chamada. Global, e
/// não por thread, para não deixar destrutor de thread pendurado num módulo
/// que o hospedeiro pode descarregar.
static PANICO: Mutex<Option<String>> = Mutex::new(None);

thread_local! {
    /// Se a thread está dentro de uma chamada: o gancho de `panic` só cala o
    /// que acontece aqui, e deixa o resto do processo com o dele.
    static DENTRO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Roda o corpo de uma função exportada: converte um `panic` em
/// `CKR_GENERAL_ERROR`, com mensagem e local no registro, e anota a chamada.
pub fn chamada(nome: &'static str, campos: Value, corpo: impl FnOnce() -> CK_RV) -> CK_RV {
    instalar_gancho();
    let inicio = Instant::now();
    let fora = DENTRO.replace(true);
    let rv = match panic::catch_unwind(AssertUnwindSafe(corpo)) {
        Ok(rv) => {
            let duracao = inicio.elapsed().as_millis();
            // Anotar nunca derruba a chamada que deveria explicar.
            let _ = panic::catch_unwind(|| anotar(nome, campos, rv, duracao, None));
            rv
        }
        Err(_) => {
            let duracao = inicio.elapsed().as_millis();
            let mensagem = trava(&PANICO).take().unwrap_or_default();
            let _ = panic::catch_unwind(|| {
                anotar(nome, campos, CKR_GENERAL_ERROR, duracao, Some(mensagem))
            });
            CKR_GENERAL_ERROR
        }
    };
    DENTRO.set(fora);
    rv
}

/// Um evento de dentro de uma operação (a falha que o agente devolveu),
/// gravado depois do anel.
pub fn evento(tipo: &str, campos: Value) {
    let mut registro = trava(&REGISTRO);
    descarregar(&mut registro);
    gravar(agora(), tipo, campos);
}

fn diretorio() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_REGISTRO) {
        return Some(PathBuf::from(dir));
    }
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(estado) if !estado.is_empty() => PathBuf::from(estado),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".local/state"),
    };
    Some(base.join("remote-certificate"))
}

/// O nome do processo hospedeiro, para saber de qual programa veio a linha.
fn processo() -> String {
    fs::read_to_string("/proc/self/comm")
        .map(|nome| nome.trim().to_string())
        .unwrap_or_default()
}

/// Uma linha no arquivo. Falhar em gravar não é problema de quem chamou.
fn gravar(t: u64, tipo: &str, campos: Value) {
    let Some(dir) = diretorio() else {
        return;
    };
    if DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .is_err()
    {
        return;
    }
    let arquivo = dir.join(ARQUIVO);
    if fs::metadata(&arquivo).is_ok_and(|m| m.len() > TAMANHO_MAXIMO) {
        let _ = fs::rename(&arquivo, dir.join(format!("{ARQUIVO}.1")));
    }
    let mut linha = Map::new();
    linha.insert("t".into(), json!(t));
    linha.insert("pid".into(), json!(std::process::id()));
    linha.insert("processo".into(), json!(processo()));
    linha.insert("tipo".into(), json!(tipo));
    if let Value::Object(campos) = campos {
        linha.extend(campos);
    }
    let Ok(mut texto) = serde_json::to_vec(&Value::Object(linha)) else {
        return;
    };
    texto.push(b'\n');
    if let Ok(mut aberto) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&arquivo)
    {
        let _ = aberto.write_all(&texto);
    }
}

/// Leva ao disco o que está no anel.
fn descarregar(registro: &mut Registro) {
    if registro.omitidas > 0 {
        gravar(
            agora(),
            "pkcs11_omitidas",
            json!({ "chamadas": registro.omitidas }),
        );
        registro.omitidas = 0;
    }
    for (t, campos) in registro.contexto.drain(..) {
        gravar(t, "pkcs11", campos);
    }
}

fn anotar(nome: &str, campos: Value, rv: CK_RV, ms: u128, panico: Option<String>) {
    let importa = panico.is_some()
        || OPERACOES.contains(&nome)
        || !matches!(rv, CKR_OK | CKR_BUFFER_TOO_SMALL);
    let mut linha = Map::new();
    linha.insert("funcao".into(), json!(nome));
    if let Value::Object(campos) = campos {
        linha.extend(campos);
    }
    linha.insert("rv".into(), json!(nome_do_rv(rv)));
    linha.insert("ms".into(), json!(ms));
    if let Some(panico) = panico {
        linha.insert("panico".into(), json!(panico));
    }
    let mut registro = trava(&REGISTRO);
    if importa {
        descarregar(&mut registro);
        gravar(agora(), "pkcs11", Value::Object(linha));
    } else {
        if registro.contexto.len() == CONTEXTO {
            registro.contexto.pop_front();
            registro.omitidas += 1;
        }
        registro.contexto.push_back((agora(), Value::Object(linha)));
    }
}

/// Troca o gancho de `panic` uma vez por processo. Dentro de uma chamada, a
/// mensagem vai para o registro e não para o stderr do hospedeiro; fora,
/// segue para o gancho que já havia.
fn instalar_gancho() {
    static UMA_VEZ: Once = Once::new();
    UMA_VEZ.call_once(|| {
        let anterior = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !DENTRO.get() {
                return anterior(info);
            }
            let mensagem = info.payload_as_str().unwrap_or("sem mensagem");
            let texto = match info.location() {
                Some(l) => format!("{mensagem} ({}:{})", l.file(), l.line()),
                None => mensagem.to_string(),
            };
            *trava(&PANICO) = Some(texto);
        }));
    });
}

/// O mecanismo pelo nome, quando é um que se espera ver aqui.
pub fn mecanismo(tipo: CK_MECHANISM_TYPE) -> String {
    let nome = match tipo {
        CKM_RSA_PKCS => "CKM_RSA_PKCS",
        CKM_RSA_X_509 => "CKM_RSA_X_509",
        CKM_RSA_PKCS_PSS => "CKM_RSA_PKCS_PSS",
        CKM_SHA1_RSA_PKCS => "CKM_SHA1_RSA_PKCS",
        CKM_SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        CKM_SHA384_RSA_PKCS => "CKM_SHA384_RSA_PKCS",
        CKM_SHA512_RSA_PKCS => "CKM_SHA512_RSA_PKCS",
        CKM_SHA256_RSA_PKCS_PSS => "CKM_SHA256_RSA_PKCS_PSS",
        CKM_SHA384_RSA_PKCS_PSS => "CKM_SHA384_RSA_PKCS_PSS",
        CKM_SHA512_RSA_PKCS_PSS => "CKM_SHA512_RSA_PKCS_PSS",
        CKM_ECDSA => "CKM_ECDSA",
        _ => return format!("0x{tipo:x}"),
    };
    nome.to_string()
}

/// O mecanismo de um ponteiro do hospedeiro, que pode ser nulo.
///
/// # Safety
///
/// `p` é nulo ou aponta para um `CK_MECHANISM`.
pub unsafe fn mecanismo_de(p: *const CK_MECHANISM) -> Option<String> {
    unsafe { p.as_ref() }.map(|m| mecanismo(m.mechanism))
}

/// Os tipos dos atributos de um modelo, sem os valores: num modelo de busca o
/// valor pode ser o serial ou o titular.
///
/// # Safety
///
/// `modelo` é nulo ou aponta para `quantos` atributos.
pub unsafe fn atributos(modelo: *const CK_ATTRIBUTE, quantos: CK_ULONG) -> Vec<String> {
    if modelo.is_null() {
        return Vec::new();
    }
    let n = (quantos as usize).min(ATRIBUTOS);
    unsafe { std::slice::from_raw_parts(modelo, n) }
        .iter()
        .map(|a| format!("0x{:x}", a.type_))
        .collect()
}

/// Tamanho e impressão digital de bytes que não podem ir ao registro, como o
/// que vai ser assinado.
pub fn impressao(dados: &[u8]) -> Value {
    let hash: String = Sha256::digest(dados)[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    json!({ "bytes": dados.len(), "sha256": hash })
}

pub fn nome_do_rv(rv: CK_RV) -> String {
    let nome = match rv {
        CKR_OK => "CKR_OK",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        _ => return format!("0x{rv:x}"),
    };
    nome.to_string()
}

fn agora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn nomes_conhecidos_e_o_resto_em_hexadecimal() {
        assert_eq!(nome_do_rv(CKR_PIN_LOCKED), "CKR_PIN_LOCKED");
        assert_eq!(nome_do_rv(0x8000_0001), "0x80000001");
        assert_eq!(mecanismo(CKM_RSA_PKCS_PSS), "CKM_RSA_PKCS_PSS");
        assert_eq!(mecanismo(0x1234), "0x1234");
    }

    #[test]
    fn impressao_nao_carrega_os_dados() {
        let v = impressao(b"conteudo secreto").to_string();
        assert!(!v.contains("conteudo"), "{v}");
        assert!(v.contains(r#""bytes":16"#), "{v}");
    }
}
