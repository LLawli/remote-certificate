//! De ponta a ponta com o cartão virtual do gdburti-rs, que imita o applet da
//! GD Burti (os mesmos APDUs do SafeSign, RSA 2048 e certificado
//! autoassinado). Não roda no CI: o gdburti-rs não é publicado. Como rodar
//! está no README deste driver.
//!
//! O cartão virtual tem o PIN de usuário `1234`, com 3 tentativas que voltam
//! ao máximo a cada `C_Initialize`, ou seja, a cada partida do driver.

mod comum;

use std::path::PathBuf;

use comum::{Driver, assinar_com_cada_mecanismo, diretorio, tipo_do_erro};
use serde_json::json;

const PIN: &str = "1234";
const SERIE: &str = "0011223344556677";

fn modulo() -> PathBuf {
    std::env::var_os("GDBURTI_PKCS11")
        .map(PathBuf::from)
        .expect("GDBURTI_PKCS11 aponta para o libgdburti_pkcs11.so do gdburti-rs")
}

fn subir(nome: &str) -> (Driver, PathBuf) {
    let estado = diretorio(nome);
    let driver = Driver::subir(&modulo(), &estado, &[("GDBURTI_VIRTUAL_CARD", "memoria")]);
    (driver, estado)
}

#[test]
#[ignore = "precisa do gdburti-rs: GDBURTI_PKCS11=<libgdburti_pkcs11.so>"]
fn configura_lista_e_assina_com_cada_mecanismo() {
    let (mut driver, estado) = subir("virtual-fluxo");
    let apresentacao = driver.apresentar();
    assert_eq!(apresentacao["driver"], "gd-burti");

    // Sem série, vale o único token conectado, e a série fica gravada.
    let configurado = driver.configurar("", PIN);
    assert_eq!(configurado["ok"], json!({"guardar": {}}), "{configurado}");
    let gravado = std::fs::read_to_string(estado.join("configuracao.json")).unwrap();
    assert_eq!(gravado, format!(r#"{{"serie":"{SERIE}"}}"#));

    let listagem = driver.listar();
    let chaves = listagem["ok"]["chaves"].as_array().unwrap().clone();
    assert_eq!(chaves.len(), 1, "{listagem}");
    let chave = &chaves[0];
    assert_eq!(chave["rotulo"], "Titular Virtual");
    // O applet assina RSA PKCS#1 v1.5 e PSS: o token se anuncia para TLS 1.3.
    let esperados = [
        "CKM_RSA_PKCS",
        "CKM_SHA256_RSA_PKCS",
        "CKM_SHA384_RSA_PKCS",
        "CKM_SHA512_RSA_PKCS",
        "CKM_RSA_PKCS_PSS",
    ];
    assert_eq!(chave["mecanismos"], json!(esperados));

    let assinados = assinar_com_cada_mecanismo(&mut driver, chave, PIN);
    assert_eq!(assinados, esperados);

    // Uma chave RSA não assina ECDSA, e o driver recusa sem pedir o PIN.
    let id = chave["id"].as_str().unwrap();
    let resposta = driver.assinar(id, "CKM_ECDSA", &[0; 32], PIN);
    assert_eq!(tipo_do_erro(&resposta), "mecanismo_nao_suportado");

    let stderr = driver.encerrar().replace(id, "");
    assert!(!stderr.contains(PIN), "o PIN apareceu no log: {stderr}");
}

#[test]
#[ignore = "precisa do gdburti-rs: GDBURTI_PKCS11=<libgdburti_pkcs11.so>"]
fn pin_errado_e_recusado_e_o_token_bloqueia() {
    let (mut driver, _estado) = subir("virtual-bloqueio");
    driver.apresentar();
    assert!(driver.configurar("", PIN).get("ok").is_some());
    let listagem = driver.listar();
    let id = listagem["ok"]["chaves"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let dados = [0x5a; 32];

    // O PIN guardado não confere: fator_recusado, sem pedir de novo.
    let resposta = driver.assinar(&id, "CKM_RSA_PKCS_PSS", &dados, "9999");
    assert_eq!(tipo_do_erro(&resposta), "fator_recusado", "{resposta}");

    // Um servidor que ignorasse a regra e insistisse esgotaria as tentativas
    // do token; a terceira errada pode já voltar como bloqueado.
    let resposta = driver.assinar(&id, "CKM_RSA_PKCS_PSS", &dados, "9998");
    assert_eq!(tipo_do_erro(&resposta), "fator_recusado", "{resposta}");
    let resposta = driver.assinar(&id, "CKM_RSA_PKCS_PSS", &dados, "9997");
    let terceira = tipo_do_erro(&resposta).to_owned();
    eprintln!("a terceira tentativa errada voltou como {terceira}");
    assert!(
        terceira == "fator_recusado" || terceira == "bloqueado",
        "{resposta}"
    );

    // Travado, o driver responde bloqueado antes de pedir o PIN, mesmo o certo.
    let resposta = driver.pedir(json!({
        "op": "assinar", "chave": id, "mecanismo": "CKM_RSA_PKCS_PSS",
        "dados": "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=",
    }));
    assert!(resposta.get("pedir").is_none(), "pediu o PIN: {resposta}");
    assert_eq!(tipo_do_erro(&resposta), "bloqueado", "{resposta}");
    // E o configurar também não gasta tentativa num token travado.
    assert_eq!(tipo_do_erro(&driver.configurar("", PIN)), "bloqueado");

    let stderr = driver.encerrar().replace(&id, "");
    for pin in [PIN, "9999", "9998", "9997"] {
        assert!(
            !stderr.contains(pin),
            "o PIN {pin} apareceu no log: {stderr}"
        );
    }
}

#[test]
#[ignore = "precisa do gdburti-rs: GDBURTI_PKCS11=<libgdburti_pkcs11.so>"]
fn configurar_com_pin_errado_nao_grava_e_serie_errada_e_token_ausente() {
    let (mut driver, estado) = subir("virtual-configurar");
    driver.apresentar();
    assert_eq!(
        tipo_do_erro(&driver.configurar("", "0000")),
        "fator_recusado"
    );
    assert!(!estado.join("configuracao.json").exists());
    assert_eq!(tipo_do_erro(&driver.listar()), "nao_configurado");
    assert_eq!(
        tipo_do_erro(&driver.configurar("FFFFFFFFFFFFFFFF", PIN)),
        "token_ausente"
    );
    driver.encerrar();
}
