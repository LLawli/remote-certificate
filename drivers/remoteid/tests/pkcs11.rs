//! A face PKCS#11 pela fronteira C, do jeito que o NSS a percorre: pelos
//! ponteiros da `CK_FUNCTION_LIST`, com o agente, o servidor, o driver
//! RemoteID e o servidor falso do RemoteID-linux de verdade, e a janela do OTP
//! respondendo no lugar da pessoa.
//!
//! Um `#[test]` só, num arquivo só dele, de propósito: o estado do módulo é
//! global por processo, como o Cryptoki manda, e o caminho do socket do
//! agente vem do ambiente, que precisa ser escrito antes de qualquer thread.
//!
//! Precisa de `REMOTEID_BIN` e `REMOTEID_MOCK_BIN`: `eval "$(scripts/remoteid.sh)"`.

// Este teste é o hospedeiro do módulo: só fala com ele por ponteiros crus.
#![allow(unsafe_code)]

mod comum;

use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use comum::*;
use cryptoki_sys::*;
use protocolo::Segredo;
use rsa::PublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use servidor::banco::travar;
use servidor::pin;
use servidor::servico::{self, Estado};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

/// Chama uma função da tabela.
macro_rules! chamar {
    ($nome:ident($($arg:expr),* $(,)?)) => {
        unsafe { (funcoes().$nome.expect(stringify!($nome)))($($arg),*) }
    };
}

fn funcoes() -> &'static CK_FUNCTION_LIST {
    let mut lista = ptr::null_mut();
    let rv = unsafe { remote_certificate_pkcs11::C_GetFunctionList(&mut lista) };
    assert_eq!(rv, CKR_OK);
    unsafe { &*lista }
}

fn slots() -> Vec<CK_SLOT_ID> {
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_GetSlotList(CK_TRUE, ptr::null_mut(), &mut n)),
        CKR_OK
    );
    let mut lista = vec![0; n as usize];
    assert_eq!(
        chamar!(C_GetSlotList(CK_TRUE, lista.as_mut_ptr(), &mut n)),
        CKR_OK
    );
    lista
}

fn info_do_token(slot: CK_SLOT_ID) -> CK_TOKEN_INFO {
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(chamar!(C_GetTokenInfo(slot, &mut info)), CKR_OK);
    info
}

fn buscar(sessao: CK_SESSION_HANDLE, classe: CK_OBJECT_CLASS) -> Vec<CK_OBJECT_HANDLE> {
    let mut valor = classe;
    let mut gabarito = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut valor).cast(),
        ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        chamar!(C_FindObjectsInit(sessao, gabarito.as_mut_ptr(), 1)),
        CKR_OK
    );
    let mut achados = [0; 16];
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_FindObjects(sessao, achados.as_mut_ptr(), 16, &mut n)),
        CKR_OK
    );
    assert_eq!(chamar!(C_FindObjectsFinal(sessao)), CKR_OK);
    achados[..n as usize].to_vec()
}

/// Um atributo em duas passadas, como manda a especificação.
fn atributo(
    sessao: CK_SESSION_HANDLE,
    objeto: CK_OBJECT_HANDLE,
    tipo: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    let mut modelo = [CK_ATTRIBUTE {
        type_: tipo,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        chamar!(C_GetAttributeValue(sessao, objeto, modelo.as_mut_ptr(), 1)),
        CKR_OK
    );
    let mut valor = vec![0u8; modelo[0].ulValueLen as usize];
    modelo[0].pValue = valor.as_mut_ptr().cast();
    assert_eq!(
        chamar!(C_GetAttributeValue(sessao, objeto, modelo.as_mut_ptr(), 1)),
        CKR_OK
    );
    valor
}

fn entrar(sessao: CK_SESSION_HANDLE, pin: &str) -> CK_RV {
    let mut pin = pin.as_bytes().to_vec();
    chamar!(C_Login(
        sessao,
        CKU_USER,
        pin.as_mut_ptr(),
        pin.len() as CK_ULONG
    ))
}

fn iniciar(
    sessao: CK_SESSION_HANDLE,
    mecanismo: CK_MECHANISM_TYPE,
    chave: CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut mecanismo = CK_MECHANISM {
        mechanism: mecanismo,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    chamar!(C_SignInit(sessao, &mut mecanismo, chave))
}

/// `C_Sign` em duas passadas: primeiro o tamanho, depois a assinatura.
fn assinar(sessao: CK_SESSION_HANDLE, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let mut dados = dados.to_vec();
    let mut n: CK_ULONG = 0;
    let rv = chamar!(C_Sign(
        sessao,
        dados.as_mut_ptr(),
        dados.len() as CK_ULONG,
        ptr::null_mut(),
        &mut n
    ));
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut assinatura = vec![0u8; n as usize];
    let rv = chamar!(C_Sign(
        sessao,
        dados.as_mut_ptr(),
        dados.len() as CK_ULONG,
        assinatura.as_mut_ptr(),
        &mut n
    ));
    if rv != CKR_OK {
        return Err(rv);
    }
    assinatura.truncate(n as usize);
    Ok(assinatura)
}

fn publica_do_certificado(der: &[u8]) -> PublicKey {
    let certificado = Certificate::from_der(der).expect("X.509 em DER");
    let spki = certificado
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    PublicKey::from_public_key_der(&spki).expect("chave RSA")
}

const PREFIXO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[test]
fn a_face_e_um_token_local_que_assina_com_o_pin_pessoal_e_a_janela_do_otp() {
    let dir = diretorio("pkcs11");
    let socket = dir.join("execucao").join("agente.sock");
    let registro = dir.join("registro");
    // Antes de qualquer thread: o ambiente é do processo inteiro.
    unsafe {
        std::env::set_var(ipc::ENV_SOCKET, &socket);
        std::env::set_var(remote_certificate_pkcs11::registro::ENV_REGISTRO, &registro);
    }

    // Antes do agente: o slot vazio, para quem lista em laço não travar.
    assert_eq!(chamar!(C_Initialize(ptr::null_mut())), CKR_OK);
    let vazio = slots();
    assert_eq!(vazio.len(), 1);
    assert_eq!(info_do_token(vazio[0]).flags & CKF_LOGIN_REQUIRED, 0);
    assert_eq!(chamar!(C_Finalize(ptr::null_mut())), CKR_OK);

    let mock = Mock::subir();
    let banco = banco(&dir);
    token_no_banco(&dir, &mock, &banco);
    let hash = pin::hash(&Segredo::novo(PIN_PESSOAL.into())).unwrap();
    let maria = travar(&banco).criar_usuario("maria", &hash).unwrap();
    let execucao = tokio::runtime::Runtime::new().unwrap();
    let endereco = execucao.block_on(async {
        let ouvinte = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endereco = ouvinte.local_addr().unwrap().to_string();
        let estado = Estado::iniciar(banco.clone(), &lancador(&dir)).unwrap();
        tokio::spawn(servico::servir(ouvinte, estado));
        endereco
    });
    let codigo = servico::novo_pareamento(&banco, maria, "notebook").unwrap();
    let pareamento = execucao
        .block_on(agente::novo_pareamento(&endereco, &codigo))
        .unwrap();
    let janela = Arc::new(JanelaDeTeste::default());
    let agente = agente::Agente::novo(pareamento, janela.clone());
    let ouvir = socket.clone();
    execucao.spawn(async move { agente::unix::ouvir(agente, &ouvir).await });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // O token do servidor aparece como um token local que pede login.
    assert_eq!(chamar!(C_Initialize(ptr::null_mut())), CKR_OK);
    let lista = slots();
    assert_eq!(lista.len(), 1);
    let slot = lista[0];
    let info = info_do_token(slot);
    assert!(info.label.starts_with(b"RemoteID "), "{:?}", info.label);
    assert_ne!(info.flags & CKF_LOGIN_REQUIRED, 0);
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_GetMechanismList(slot, ptr::null_mut(), &mut n)),
        CKR_OK
    );
    let mut mecanismos = vec![0; n as usize];
    assert_eq!(
        chamar!(C_GetMechanismList(slot, mecanismos.as_mut_ptr(), &mut n)),
        CKR_OK
    );
    assert!(mecanismos.contains(&CKM_RSA_PKCS) && mecanismos.contains(&CKM_SHA256_RSA_PKCS));
    assert!(
        !mecanismos.contains(&CKM_RSA_PKCS_PSS),
        "a Certisign não assina PSS"
    );

    let mut sessao = 0;
    assert_eq!(
        chamar!(C_OpenSession(
            slot,
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut sessao
        )),
        CKR_OK
    );
    let [certificado] = buscar(sessao, CKO_CERTIFICATE)[..] else {
        panic!("um certificado");
    };
    let [privada] = buscar(sessao, CKO_PRIVATE_KEY)[..] else {
        panic!("uma chave privada");
    };
    let [publica] = buscar(sessao, CKO_PUBLIC_KEY)[..] else {
        panic!("uma chave pública");
    };
    assert_eq!(
        atributo(sessao, certificado, CKA_ID),
        atributo(sessao, privada, CKA_ID),
        "o NSS pareia o certificado e a chave pelo CKA_ID"
    );
    let chave = publica_do_certificado(&atributo(sessao, certificado, CKA_VALUE));

    // Sem o C_Login não assina; o PIN errado conta e aparece nos flags.
    assert_eq!(
        iniciar(sessao, CKM_SHA256_RSA_PKCS, privada),
        CKR_USER_NOT_LOGGED_IN
    );
    assert_eq!(entrar(sessao, "0000"), CKR_PIN_INCORRECT);
    assert_ne!(info_do_token(slot).flags & CKF_USER_PIN_COUNT_LOW, 0);
    assert_eq!(entrar(sessao, PIN_PESSOAL), CKR_OK);
    let mut estado: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(chamar!(C_GetSessionInfo(sessao, &mut estado)), CKR_OK);
    assert_eq!(estado.state, CKS_RO_USER_FUNCTIONS);

    // O poppler: C_Sign de uma parte. A janela pede o OTP; o errado volta.
    janela.codigos.lock().unwrap().extend(["999999", OTP]);
    assert_eq!(iniciar(sessao, CKM_SHA256_RSA_PKCS, privada), CKR_OK);
    let assinatura = assinar(sessao, DOCUMENTO).expect("assina");
    chave
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(DOCUMENTO),
            &assinatura,
        )
        .expect("a assinatura confere com o certificado do token");
    assert_eq!(janela.perguntas.lock().unwrap().len(), 2);

    // O PJeOffice (BouncyCastle): C_SignUpdate em pedaços e C_SignFinal. A
    // sessão do RemoteID aberta pelo OTP atende sem perguntar.
    assert_eq!(iniciar(sessao, CKM_SHA256_RSA_PKCS, privada), CKR_OK);
    let (comeco, fim) = DOCUMENTO.split_at(7);
    for pedaco in [comeco, fim] {
        let mut pedaco = pedaco.to_vec();
        assert_eq!(
            chamar!(C_SignUpdate(
                sessao,
                pedaco.as_mut_ptr(),
                pedaco.len() as CK_ULONG
            )),
            CKR_OK
        );
    }
    let mut assinatura = vec![0u8; 512];
    let mut n = assinatura.len() as CK_ULONG;
    assert_eq!(
        chamar!(C_SignFinal(sessao, assinatura.as_mut_ptr(), &mut n)),
        CKR_OK
    );
    assinatura.truncate(n as usize);
    chave
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(DOCUMENTO),
            &assinatura,
        )
        .expect("a assinatura em pedaços confere");

    // O TLS 1.2 do navegador: CKM_RSA_PKCS sobre um DigestInfo pronto.
    let resumo = Sha256::digest(b"handshake");
    assert_eq!(iniciar(sessao, CKM_RSA_PKCS, privada), CKR_OK);
    let assinatura = assinar(sessao, &[&PREFIXO_SHA256[..], &resumo].concat()).unwrap();
    chave
        .verify(Pkcs1v15Sign::new::<Sha256>(), &resumo, &assinatura)
        .expect("o DigestInfo pronto confere");

    // A janela aberta não segura o módulo: com a pessoa lenta, a mesma
    // aplicação lista e lê o token na hora.
    mock.expirar_sessoes();
    *janela.demora.lock().unwrap() = Duration::from_secs(2);
    janela.codigos.lock().unwrap().push_back(OTP);
    let lenta = std::thread::spawn(move || {
        assert_eq!(iniciar(sessao, CKM_SHA256_RSA_PKCS, privada), CKR_OK);
        assinar(sessao, DOCUMENTO)
    });
    std::thread::sleep(Duration::from_millis(500));
    let comeco = Instant::now();
    assert_eq!(slots(), [slot]);
    info_do_token(slot);
    let mut outra = 0;
    assert_eq!(
        chamar!(C_OpenSession(
            slot,
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut outra
        )),
        CKR_OK
    );
    assert!(
        comeco.elapsed() < Duration::from_millis(500),
        "esperou a janela: {:?}",
        comeco.elapsed()
    );
    assert!(lenta.join().unwrap().is_ok());
    *janela.demora.lock().unwrap() = Duration::ZERO;

    // Fechar a janela cancela.
    mock.expirar_sessoes();
    assert_eq!(iniciar(sessao, CKM_SHA256_RSA_PKCS, privada), CKR_OK);
    assert_eq!(assinar(sessao, DOCUMENTO), Err(CKR_FUNCTION_CANCELED));

    // O signer4j do PJeOffice cifra com a pública; a privada não cifra.
    let mut rsa_pkcs = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        chamar!(C_EncryptInit(sessao, &mut rsa_pkcs, privada)),
        CKR_KEY_FUNCTION_NOT_PERMITTED
    );
    assert_eq!(
        chamar!(C_EncryptInit(sessao, &mut rsa_pkcs, publica)),
        CKR_OK
    );
    let mut claro = b"segredo de sessao".to_vec();
    let mut cifrado = vec![0u8; 256];
    let mut n = cifrado.len() as CK_ULONG;
    assert_eq!(
        chamar!(C_Encrypt(
            sessao,
            claro.as_mut_ptr(),
            claro.len() as CK_ULONG,
            cifrado.as_mut_ptr(),
            &mut n
        )),
        CKR_OK
    );
    assert_eq!(n, 256);

    // RSA-PSS (o TLS 1.3) não é do token: "não suportado", mesmo com os
    // parâmetros dele, e não "parâmetro errado".
    let mut parametros = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mut pss = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_PSS,
        pParameter: (&raw mut parametros).cast(),
        ulParameterLen: size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        chamar!(C_SignInit(sessao, &mut pss, privada)),
        CKR_MECHANISM_INVALID
    );
    let mut com_lixo = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: (&raw mut parametros).cast(),
        ulParameterLen: size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        chamar!(C_SignInit(sessao, &mut com_lixo, privada)),
        CKR_MECHANISM_PARAM_INVALID
    );

    // O C_Logout fecha o login.
    assert_eq!(chamar!(C_Logout(sessao)), CKR_OK);
    assert_eq!(
        iniciar(sessao, CKM_SHA256_RSA_PKCS, privada),
        CKR_USER_NOT_LOGGED_IN
    );
    assert_eq!(chamar!(C_Finalize(ptr::null_mut())), CKR_OK);
    drop(execucao);

    // A auditoria tem cada assinatura que chegou ao token.
    let linhas = travar(&banco).auditoria(1000).unwrap();
    let assinaturas: Vec<_> = linhas
        .iter()
        .filter(|l| l.evento == "assinatura")
        .map(|l| l.resultado.as_str())
        .collect();
    assert_eq!(
        assinaturas,
        ["assinada", "assinada", "assinada", "assinada", "cancelada"]
    );

    // O registro da face explica o que houve sem guardar segredo.
    let texto = std::fs::read_to_string(registro.join("pkcs11.log")).expect("registro");
    assert!(texto.contains(r#""funcao":"C_Login""#), "{texto}");
    assert!(texto.contains(r#""rv":"CKR_PIN_INCORRECT""#), "{texto}");
    assert!(texto.contains(r#""rv":"CKR_FUNCTION_CANCELED""#), "{texto}");
    for segredo in [
        PIN_PESSOAL,
        OTP,
        "999999",
        "procuracao de teste",
        "segredo de sessao",
    ] {
        assert!(!texto.contains(segredo), "{segredo} no registro");
    }
}
