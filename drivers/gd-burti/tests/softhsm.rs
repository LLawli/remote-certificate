//! De ponta a ponta com o SoftHSM2 no lugar do `libaetpkss.so`: o driver
//! sobe, conversa pelo contrato e assina com cada mecanismo que declara, e a
//! assinatura é conferida com o certificado. Roda no CI. Os tokens estão em
//! `comum::softhsm`.

mod comum;

use std::path::Path;

use comum::softhsm::{ID_DA_AC, ID_EC, ID_RSA, ID_RSA_B, PIN, modulo, preparar};
use comum::{Driver, assinar_com_cada_mecanismo, diretorio, tipo_do_erro};
use serde_json::{Value, json};

fn subir(trabalho: &Path, conf: &Path) -> Driver {
    let estado = trabalho.join("estado");
    std::fs::create_dir_all(&estado).unwrap();
    Driver::subir(
        &modulo(),
        &estado,
        &[("SOFTHSM2_CONF", conf.to_str().unwrap())],
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn chave<'a>(listagem: &'a Value, id: &[u8]) -> &'a Value {
    listagem["ok"]["chaves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == hex(id))
        .unwrap_or_else(|| panic!("sem a chave {}: {listagem}", hex(id)))
}

#[test]
fn assina_com_cada_mecanismo_de_cada_chave() {
    let trabalho = diretorio("softhsm-fluxo");
    let (conf, serie_a, _) = preparar(&trabalho);
    let mut driver = subir(&trabalho, &conf);
    let apresentacao = driver.apresentar();
    assert_eq!(apresentacao["protocolo"], protocolo::VERSAO);
    assert_eq!(
        apresentacao["fatores"],
        json!([{"nome": "pin", "tipo": "guardado", "rotulo": "PIN do token"}])
    );

    let configurado = driver.configurar(&serie_a, PIN);
    assert_eq!(configurado["ok"], json!({"guardar": {}}), "{configurado}");

    let listagem = driver.listar();
    // O certificado da AC não tem chave no token e fica de fora.
    assert_eq!(
        listagem["ok"]["chaves"].as_array().unwrap().len(),
        2,
        "{listagem}"
    );

    let rsa = chave(&listagem, ID_RSA).clone();
    assert_eq!(rsa["rotulo"], "FULANO DE TAL:00000000000");
    let esperados_rsa = [
        "CKM_RSA_PKCS",
        "CKM_SHA256_RSA_PKCS",
        "CKM_SHA384_RSA_PKCS",
        "CKM_SHA512_RSA_PKCS",
        "CKM_RSA_PKCS_PSS",
    ];
    assert_eq!(rsa["mecanismos"], json!(esperados_rsa));
    assert_eq!(
        assinar_com_cada_mecanismo(&mut driver, &rsa, PIN),
        esperados_rsa
    );

    let ec = chave(&listagem, ID_EC).clone();
    assert_eq!(ec["mecanismos"], json!(["CKM_ECDSA"]));
    assert_eq!(
        assinar_com_cada_mecanismo(&mut driver, &ec, PIN),
        ["CKM_ECDSA"]
    );

    // RSA-PSS com SHA-512: o driver deduz o hash pelo tamanho.
    let mensagem = b"PSS com SHA-512";
    let hash = ring::digest::digest(&ring::digest::SHA512, mensagem);
    let resposta = driver.assinar(&hex(ID_RSA), "CKM_RSA_PKCS_PSS", hash.as_ref(), PIN);
    let certificado = comum_certificado(&rsa);
    assert!(comum::confere(
        &certificado,
        &ring::signature::RSA_PSS_2048_8192_SHA512,
        mensagem,
        &comum::assinatura(&resposta)
    ));

    let stderr = driver.encerrar();
    assert!(!stderr.contains(PIN), "o PIN apareceu no log: {stderr}");
}

fn comum_certificado(chave: &Value) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(chave["certificado"].as_str().unwrap())
        .unwrap()
}

#[test]
fn a_serie_escolhe_o_token_e_fica_para_a_proxima_partida() {
    let trabalho = diretorio("softhsm-serie");
    let (conf, _, serie_b) = preparar(&trabalho);

    // Com dois tokens conectados, sem série não dá para escolher.
    let mut driver = subir(&trabalho, &conf);
    driver.apresentar();
    let resposta = driver.configurar("", PIN);
    assert_eq!(tipo_do_erro(&resposta), "pedido_invalido");
    assert!(
        resposta["erro"]["mensagem"]
            .as_str()
            .unwrap()
            .contains(&serie_b),
        "{resposta}"
    );
    assert!(driver.configurar(&serie_b, PIN).get("ok").is_some());
    driver.encerrar();

    // Outra partida, sem configurar de novo: lista e assina no token B.
    let mut driver = subir(&trabalho, &conf);
    driver.apresentar();
    let listagem = driver.listar();
    assert_eq!(
        listagem["ok"]["chaves"].as_array().unwrap().len(),
        1,
        "{listagem}"
    );
    let b = chave(&listagem, ID_RSA_B).clone();
    let resposta = driver.assinar(&hex(ID_RSA_B), "CKM_SHA256_RSA_PKCS", b"oi", PIN);
    assert!(comum::confere(
        &comum_certificado(&b),
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        b"oi",
        &comum::assinatura(&resposta)
    ));
    driver.encerrar();
}

#[test]
fn falhas_viram_os_tipos_do_contrato() {
    let trabalho = diretorio("softhsm-falhas");
    let (conf, serie_a, _) = preparar(&trabalho);
    let mut driver = subir(&trabalho, &conf);
    driver.apresentar();

    assert_eq!(tipo_do_erro(&driver.listar()), "nao_configurado");
    assert_eq!(
        tipo_do_erro(&driver.configurar("nao-existe", PIN)),
        "token_ausente"
    );
    assert_eq!(
        tipo_do_erro(&driver.configurar(&serie_a, "0000")),
        "fator_recusado"
    );
    assert!(driver.configurar(&serie_a, PIN).get("ok").is_some());

    // Recusas que não gastam o PIN: o driver não chega a pedi-lo.
    let sem_pin = |driver: &mut Driver, chave: &[u8], mecanismo: &str, dados: &str| {
        let resposta = driver.pedir(json!({
            "op": "assinar", "chave": hex(chave), "mecanismo": mecanismo, "dados": dados,
        }));
        assert!(resposta.get("pedir").is_none(), "pediu o PIN: {resposta}");
        tipo_do_erro(&resposta).to_owned()
    };
    let hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(
        sem_pin(&mut driver, ID_RSA, "CKM_ECDSA", hash),
        "mecanismo_nao_suportado"
    );
    assert_eq!(
        sem_pin(&mut driver, ID_EC, "CKM_RSA_PKCS", hash),
        "mecanismo_nao_suportado"
    );
    assert_eq!(
        sem_pin(&mut driver, ID_RSA, "CKM_EDDSA", hash),
        "mecanismo_nao_suportado"
    );
    assert_eq!(
        sem_pin(&mut driver, ID_DA_AC, "CKM_RSA_PKCS", hash),
        "chave_ausente"
    );
    assert_eq!(
        sem_pin(&mut driver, ID_RSA, "CKM_RSA_PKCS_PSS", "AAAA"),
        "pedido_invalido"
    );

    // O PIN guardado recusado: fator_recusado, e o driver não pede de novo.
    let resposta = driver.assinar(&hex(ID_RSA), "CKM_SHA256_RSA_PKCS", b"x", "1111");
    assert_eq!(tipo_do_erro(&resposta), "fator_recusado");

    // O servidor desiste no pedido do PIN.
    let resposta = driver.pedir(json!({
        "op": "assinar", "chave": hex(ID_RSA), "mecanismo": "CKM_SHA256_RSA_PKCS", "dados": "eA==",
    }));
    let id = resposta["id"].clone();
    assert!(resposta.get("pedir").is_some());
    driver.mandar(&json!({"id": id, "cancelar": true}));
    assert_eq!(tipo_do_erro(&driver.receber()), "cancelado");

    let stderr = driver.encerrar();
    for pin in [PIN, "0000", "1111"] {
        assert!(
            !stderr.contains(pin),
            "o PIN {pin} apareceu no log: {stderr}"
        );
    }
}

/// Não é um teste: a preparação dos tokens (ver `comum::softhsm`).
#[test]
#[ignore = "auxiliar dos outros testes deste arquivo"]
fn auxiliar_preparar() {
    comum::softhsm::auxiliar();
}
