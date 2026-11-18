//! A face PKCS#11 com o driver GD Burti sobre o SoftHSM: o servidor, o
//! driver, o agente e a face juntos, e cada tipo de assinatura que o driver
//! oferece pedido como o NSS e o poppler pedem (PKCS#1 v1.5 do TLS 1.2 e do
//! PDF, RSA-PSS e ECDSA do TLS 1.3), conferido com o certificado. Roda no
//! CI, com o SoftHSM.
//!
//! Um `#[test]` só, fora o auxiliar, pelo mesmo motivo do teste da face no
//! driver RemoteID: o estado do módulo e o ambiente são do processo inteiro.

// Este teste é o hospedeiro do módulo: só fala com ele por ponteiros crus.
#![allow(unsafe_code)]

mod comum;

use std::collections::BTreeMap;
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use comum::diretorio;
use comum::softhsm::{PIN, modulo, preparar};
use cryptoki_sys::*;
use protocolo::Segredo;
use remote_certificate_pkcs11::chamar;
use remote_certificate_pkcs11::hospedeiro::*;
use remote_certificate_pkcs11::registro::ENV_REGISTRO;
use ring::digest::{SHA256, SHA384, digest};
use ring::signature;
use servidor::banco::{Banco, ChaveDoBanco, ler_chave, travar};
use servidor::driver::Driver;
use servidor::lancador::Lancador;
use servidor::pin;
use servidor::servico::{self, Estado};
use servidor::token::{GuardaNoBanco, Token};
use tokio::net::TcpListener;
use x509_parser::prelude::{FromDer, X509Certificate};

const PIN_PESSOAL: &str = "pessoal-2468";
const DOCUMENTO: &[u8] = b"procuracao de teste";

/// O GD Burti só tem o PIN, guardado no servidor: nada é perguntado à pessoa.
struct SemJanela;

impl agente::dialogo::Dialogo for SemJanela {
    fn perguntar(&self, _: &agente::dialogo::Pergunta) -> Option<BTreeMap<String, Segredo>> {
        panic!("o GD Burti não pergunta nada à pessoa");
    }
}

/// A chave privada do tipo pedido e o certificado dela (pelo `CKA_ID`).
fn chave_do_tipo(sessao: CK_SESSION_HANDLE, tipo: CK_KEY_TYPE) -> (CK_OBJECT_HANDLE, Vec<u8>) {
    let privada = buscar(sessao, CKO_PRIVATE_KEY)
        .into_iter()
        .find(|&h| atributo(sessao, h, CKA_KEY_TYPE) == tipo.to_ne_bytes())
        .unwrap_or_else(|| panic!("sem chave do tipo {tipo}"));
    let id = atributo(sessao, privada, CKA_ID);
    let certificado = buscar(sessao, CKO_CERTIFICATE)
        .into_iter()
        .find(|&h| atributo(sessao, h, CKA_ID) == id)
        .expect("o certificado com o CKA_ID da chave");
    (privada, atributo(sessao, certificado, CKA_VALUE))
}

fn confere(
    certificado: &[u8],
    algoritmo: &'static dyn signature::VerificationAlgorithm,
    mensagem: &[u8],
    assinatura: &[u8],
) {
    assert!(
        comum::confere(certificado, algoritmo, mensagem, assinatura),
        "a assinatura não confere com o certificado"
    );
}

#[test]
fn a_face_assina_com_cada_mecanismo_do_driver_e_mostra_o_token_para_tls_13() {
    let trabalho = diretorio("pkcs11");
    let (conf, serie_a, _) = preparar(&trabalho);
    let socket = trabalho.join("execucao").join("agente.sock");
    let registro = trabalho.join("registro");
    // Antes de qualquer thread: o ambiente é do processo inteiro, e o driver
    // que o servidor sobe herda o SOFTHSM2_CONF.
    unsafe {
        std::env::set_var(ipc::ENV_SOCKET, &socket);
        std::env::set_var(ENV_REGISTRO, &registro);
        std::env::set_var("SOFTHSM2_CONF", &conf);
    }

    // O servidor, com o token criado e configurado como o administrador faria.
    let arquivo = trabalho.join("chave");
    std::fs::write(&arquivo, ChaveDoBanco::aleatorio().unwrap().expor()).unwrap();
    let banco = Banco::abrir(&trabalho.join("banco.db"), ler_chave(&arquivo).unwrap()).unwrap();
    let banco = Arc::new(Mutex::new(banco));
    let lancador = Lancador::novo("/", trabalho.join("estados"));
    let argumentos = ["--modulo".to_string(), modulo().display().to_string()];
    let id = travar(&banco)
        .criar_token(
            "GD",
            env!("CARGO_BIN_EXE_remote-certificate-driver-gd-burti"),
            &argumentos,
        )
        .unwrap();
    let registro_do_token = travar(&banco)
        .tokens()
        .unwrap()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap();
    let mut comando: Command = lancador.comando(&registro_do_token).unwrap();
    Token::abrir(
        Driver::lancar(&mut comando).unwrap(),
        GuardaNoBanco::novo(banco.clone(), id),
    )
    .unwrap()
    .configurar(BTreeMap::from([
        ("serie".to_string(), Segredo::novo(serie_a)),
        ("pin".to_string(), Segredo::novo(PIN.into())),
    ]))
    .unwrap();
    let hash = pin::hash(&Segredo::novo(PIN_PESSOAL.into())).unwrap();
    let maria = travar(&banco).criar_usuario("maria", &hash).unwrap();
    let execucao = tokio::runtime::Runtime::new().unwrap();
    let endereco = execucao.block_on(async {
        let ouvinte = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endereco = ouvinte.local_addr().unwrap().to_string();
        let estado = Estado::iniciar(banco.clone(), &lancador).unwrap();
        tokio::spawn(servico::servir(ouvinte, estado));
        endereco
    });

    // A estação pareada, com o agente ouvindo a face.
    let codigo = servico::novo_pareamento(&banco, maria, "notebook").unwrap();
    let pareamento = execucao
        .block_on(agente::novo_pareamento(&endereco, &codigo))
        .unwrap();
    let agente = agente::Agente::novo(pareamento, Arc::new(SemJanela));
    let ouvir = socket.clone();
    execucao.spawn(async move { agente::unix::ouvir(agente, &ouvir).await });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // O token anuncia o que o driver declarou: RSA-PSS e ECDSA servem ao TLS
    // 1.3, e o ECDSA diz a curva que aceita.
    assert_eq!(chamar!(C_Initialize(ptr::null_mut())), CKR_OK);
    let [slot] = slots()[..] else {
        panic!("um slot");
    };
    let anunciados = mecanismos(slot);
    for esperado in [
        CKM_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_ECDSA,
    ] {
        assert!(anunciados.contains(&esperado), "{anunciados:?}");
    }
    let ecdsa = info_do_mecanismo(slot, CKM_ECDSA).unwrap();
    assert_eq!((ecdsa.ulMinKeySize, ecdsa.ulMaxKeySize), (256, 256));
    assert_ne!(ecdsa.flags & CKF_SIGN, 0);
    assert_ne!(ecdsa.flags & CKF_EC_NAMEDCURVE, 0);
    let pss = info_do_mecanismo(slot, CKM_RSA_PKCS_PSS).unwrap();
    assert_eq!((pss.ulMinKeySize, pss.ulMaxKeySize), (2048, 2048));
    assert_eq!(pss.flags, CKF_SIGN, "o PSS só assina");

    let sessao = abrir_sessao(slot);
    let (rsa, certificado_rsa) = chave_do_tipo(sessao, CKK_RSA);
    let (ec, certificado_ec) = chave_do_tipo(sessao, CKK_EC);

    // A chave pública EC é a do certificado, ponto por ponto.
    let publica_ec = buscar(sessao, CKO_PUBLIC_KEY)
        .into_iter()
        .find(|&h| atributo(sessao, h, CKA_ID) == atributo(sessao, ec, CKA_ID))
        .unwrap();
    let ponto = atributo(sessao, publica_ec, CKA_EC_POINT);
    let (_, lido) = X509Certificate::from_der(&certificado_ec).unwrap();
    assert_eq!(ponto[2..], *lido.public_key().subject_public_key.data);
    assert_eq!(
        atributo(sessao, ec, CKA_EC_PARAMS),
        atributo(sessao, publica_ec, CKA_EC_PARAMS)
    );

    assert_eq!(entrar(sessao, PIN_PESSOAL), CKR_OK);

    // O TLS 1.3 com RSA: o NSS passa o hash e os parâmetros do PSS.
    let parametros = |hash, mgf, sal| CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: hash,
        mgf,
        sLen: sal,
    };
    let transcricao = b"transcricao do handshake";
    for (hash, mgf, bytes, algoritmo, verificacao) in [
        (
            CKM_SHA256,
            CKG_MGF1_SHA256,
            32,
            &SHA256,
            &signature::RSA_PSS_2048_8192_SHA256,
        ),
        (
            CKM_SHA384,
            CKG_MGF1_SHA384,
            48,
            &SHA384,
            &signature::RSA_PSS_2048_8192_SHA384,
        ),
    ] {
        let pss = parametros(hash, mgf, bytes);
        assert_eq!(iniciar_com_pss(sessao, CKM_RSA_PKCS_PSS, pss, rsa), CKR_OK);
        let assinatura = assinar(sessao, digest(algoritmo, transcricao).as_ref()).unwrap();
        assert_eq!(assinatura.len(), 256);
        confere(&certificado_rsa, verificacao, transcricao, &assinatura);
    }

    // Parâmetros que dariam uma assinatura que não confere ficam na porta,
    // sem chegar ao token.
    let mgf_trocado = parametros(CKM_SHA256, CKG_MGF1_SHA1, 32);
    assert_eq!(
        iniciar_com_pss(sessao, CKM_RSA_PKCS_PSS, mgf_trocado, rsa),
        CKR_MECHANISM_PARAM_INVALID
    );
    assert_eq!(
        iniciar(sessao, CKM_RSA_PKCS_PSS, rsa),
        CKR_MECHANISM_PARAM_INVALID,
        "o PSS sem parâmetros"
    );
    let sha256 = parametros(CKM_SHA256, CKG_MGF1_SHA256, 32);
    assert_eq!(
        iniciar_com_pss(sessao, CKM_RSA_PKCS_PSS, sha256, rsa),
        CKR_OK
    );
    assert_eq!(
        assinar(sessao, digest(&SHA384, transcricao).as_ref()),
        Err(CKR_DATA_LEN_RANGE),
        "um hash de outro tamanho que o dos parâmetros"
    );

    // O TLS 1.3 com EC: o hash, e a assinatura volta como r‖s.
    assert_eq!(iniciar(sessao, CKM_ECDSA, ec), CKR_OK);
    let assinatura = assinar(sessao, digest(&SHA256, transcricao).as_ref()).unwrap();
    assert_eq!(assinatura.len(), 64, "r‖s da P-256");
    confere(
        &certificado_ec,
        &signature::ECDSA_P256_SHA256_FIXED,
        transcricao,
        &assinatura,
    );

    // Cada chave só com os mecanismos do tipo dela.
    assert_eq!(iniciar(sessao, CKM_ECDSA, rsa), CKR_MECHANISM_INVALID);
    assert_eq!(
        iniciar_com_pss(sessao, CKM_RSA_PKCS_PSS, sha256, ec),
        CKR_MECHANISM_INVALID
    );
    assert_eq!(
        iniciar(sessao, CKM_SHA256_RSA_PKCS, ec),
        CKR_MECHANISM_INVALID
    );

    // O PDF pelo poppler, com a chave RSA, como antes.
    assert_eq!(iniciar(sessao, CKM_SHA256_RSA_PKCS, rsa), CKR_OK);
    let assinatura = assinar(sessao, DOCUMENTO).unwrap();
    confere(
        &certificado_rsa,
        &signature::RSA_PKCS1_2048_8192_SHA256,
        DOCUMENTO,
        &assinatura,
    );

    assert_eq!(chamar!(C_Finalize(ptr::null_mut())), CKR_OK);
    drop(execucao);

    // A auditoria tem cada assinatura que chegou ao token, e só elas.
    let linhas = travar(&banco).auditoria(1000).unwrap();
    let assinadas = linhas
        .iter()
        .filter(|l| l.evento == "assinatura" && l.resultado == "assinada")
        .count();
    assert_eq!(assinadas, 4);
    assert!(
        linhas
            .iter()
            .all(|l| l.evento != "assinatura" || l.resultado == "assinada"),
        "uma recusa da face chegou ao servidor"
    );

    // O registro da face não guarda segredo. O PIN do token nem passa por
    // ela: fica no servidor.
    let texto = std::fs::read_to_string(registro.join("pkcs11.log")).expect("registro");
    assert!(
        texto.contains(r#""rv":"CKR_MECHANISM_PARAM_INVALID""#),
        "{texto}"
    );
    for segredo in [PIN_PESSOAL, "procuracao de teste"] {
        assert!(!texto.contains(segredo), "{segredo} no registro");
    }
}

/// Não é um teste: a preparação dos tokens (ver `comum::softhsm`).
#[test]
#[ignore = "auxiliar do outro teste deste arquivo"]
fn auxiliar_preparar() {
    comum::softhsm::auxiliar();
}
