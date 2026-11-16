//! De ponta a ponta com o SoftHSM2 no lugar do `libaetpkss.so`: o driver
//! sobe, conversa pelo contrato e assina com cada mecanismo que declara, e a
//! assinatura é conferida com o certificado. Roda no CI.
//!
//! O SoftHSM lê a configuração de `SOFTHSM2_CONF`, que só um processo novo
//! recebe sem `unsafe`. Por isso os tokens são preparados por este mesmo
//! binário de teste, relançado com a variável no teste `auxiliar_preparar`.

mod comum;

use std::path::{Path, PathBuf};
use std::process::Command;

use comum::{Driver, assinar_com_cada_mecanismo, diretorio, tipo_do_erro};
use serde_json::{Value, json};

const PIN: &str = "4321";
const PIN_SO: &str = "87654321";
/// O certificado da AC da cadeia, que o token guarda sem a chave.
const ID_DA_AC: &[u8] = &[0xca];
const ID_RSA: &[u8] = &[0x01, 0x02];
const ID_EC: &[u8] = &[0x0e, 0xc0];
const ID_RSA_B: &[u8] = &[0xb0];

/// O módulo do SoftHSM: `SOFTHSM2_MODULE`, ou onde as distribuições o põem.
fn modulo() -> PathBuf {
    if let Some(caminho) = std::env::var_os("SOFTHSM2_MODULE") {
        return caminho.into();
    }
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
    .expect("sem o SoftHSM2: instale o pacote softhsm2 ou aponte SOFTHSM2_MODULE")
}

/// Dois tokens no SoftHSM: o A, com uma chave RSA, uma EC e o certificado de
/// uma AC; o B, com uma chave RSA. Devolve a configuração e as séries.
fn preparar(trabalho: &Path) -> (PathBuf, String, String) {
    let tokens = trabalho.join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = trabalho.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();
    let saida = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "auxiliar_preparar", "--nocapture"])
        .env("SOFTHSM2_CONF", &conf)
        .env("GD_BURTI_AUXILIAR", trabalho)
        .env("SOFTHSM2_MODULE", modulo())
        .output()
        .unwrap();
    assert!(
        saida.status.success(),
        "a preparação do SoftHSM falhou: {}{}",
        String::from_utf8_lossy(&saida.stdout),
        String::from_utf8_lossy(&saida.stderr)
    );
    let series: Value =
        serde_json::from_slice(&std::fs::read(trabalho.join("series.json")).unwrap()).unwrap();
    (
        conf,
        series["a"].as_str().unwrap().to_owned(),
        series["b"].as_str().unwrap().to_owned(),
    )
}

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

/// Não é um teste: é a preparação dos tokens, num processo com
/// `SOFTHSM2_CONF`. Sem `GD_BURTI_AUXILIAR`, não faz nada.
#[test]
#[ignore = "auxiliar dos outros testes deste arquivo"]
fn auxiliar_preparar() {
    let Some(trabalho) = std::env::var_os("GD_BURTI_AUXILIAR") else {
        return;
    };
    let series = softhsm::preparar(&modulo());
    std::fs::write(
        Path::new(&trabalho).join("series.json"),
        json!({"a": series.0, "b": series.1}).to_string(),
    )
    .unwrap();
}

mod softhsm {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{
        Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
    };
    use cryptoki::session::{Session, UserType};
    use cryptoki::types::AuthPin;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
        PublicKeyData, SerialNumber, SignatureAlgorithm, SigningKey,
    };

    use super::{ID_DA_AC, ID_EC, ID_RSA, ID_RSA_B, PIN, PIN_SO};

    /// O OID da curva P-256, como o CKA_EC_PARAMS o leva.
    const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    /// Uma chave do SoftHSM assinando o certificado pelo rcgen.
    struct NoToken<'a> {
        sessao: &'a Session,
        privada: ObjectHandle,
        publica: Vec<u8>,
        ec: bool,
    }

    impl PublicKeyData for NoToken<'_> {
        fn der_bytes(&self) -> &[u8] {
            &self.publica
        }
        fn algorithm(&self) -> &'static SignatureAlgorithm {
            if self.ec {
                &PKCS_ECDSA_P256_SHA256
            } else {
                &PKCS_RSA_SHA256
            }
        }
    }

    impl SigningKey for NoToken<'_> {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            // O SoftHSM não tem o CKM_ECDSA_SHA256: o hash vem daqui.
            let hash;
            let (mecanismo, dados) = if self.ec {
                hash = ring::digest::digest(&ring::digest::SHA256, msg);
                (Mechanism::Ecdsa, hash.as_ref())
            } else {
                (Mechanism::Sha256RsaPkcs, msg)
            };
            let assinatura = self
                .sessao
                .sign(&mecanismo, self.privada, dados)
                .map_err(|e| {
                    eprintln!("assinatura do certificado no SoftHSM: {e}");
                    rcgen::Error::RemoteKeyError
                })?;
            Ok(if self.ec {
                ecdsa_der(&assinatura)
            } else {
                assinatura
            })
        }
    }

    fn der(tag: u8, conteudo: &[u8]) -> Vec<u8> {
        let mut saida = vec![tag];
        match conteudo.len() {
            n if n < 0x80 => saida.push(n as u8),
            n if n < 0x100 => saida.extend([0x81, n as u8]),
            n => saida.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        saida.extend_from_slice(conteudo);
        saida
    }

    fn inteiro(bytes: &[u8]) -> Vec<u8> {
        let mut bytes = bytes;
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes = &bytes[1..];
        }
        let mut conteudo = Vec::new();
        if bytes[0] & 0x80 != 0 {
            conteudo.push(0);
        }
        conteudo.extend_from_slice(bytes);
        der(0x02, &conteudo)
    }

    /// r‖s do PKCS#11 para o ECDSA-Sig-Value do X.509.
    fn ecdsa_der(bruta: &[u8]) -> Vec<u8> {
        let (r, s) = bruta.split_at(bruta.len() / 2);
        der(0x30, &[inteiro(r), inteiro(s)].concat())
    }

    fn atributo(sessao: &Session, objeto: ObjectHandle, tipo: AttributeType) -> Vec<u8> {
        match sessao.get_attributes(objeto, &[tipo]).unwrap().pop() {
            Some(Attribute::Modulus(v) | Attribute::PublicExponent(v) | Attribute::EcPoint(v)) => v,
            outro => panic!("{outro:?}"),
        }
    }

    fn gerar(sessao: &Session, id: &[u8], ec: bool) -> (ObjectHandle, Vec<u8>) {
        let comuns_pub = [
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Id(id.to_vec()),
        ];
        let privada = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Id(id.to_vec()),
        ];
        if ec {
            let mut publica = comuns_pub.to_vec();
            publica.push(Attribute::EcParams(P256.to_vec()));
            let (pubk, privk) = sessao
                .generate_key_pair(&Mechanism::EccKeyPairGen, &publica, &privada)
                .unwrap();
            // CKA_EC_POINT é o ponto dentro de um OCTET STRING.
            let ponto = atributo(sessao, pubk, AttributeType::EcPoint);
            (privk, ponto[2..].to_vec())
        } else {
            let mut publica = comuns_pub.to_vec();
            publica.push(Attribute::ModulusBits(2048.into()));
            publica.push(Attribute::PublicExponent(vec![1, 0, 1]));
            let (pubk, privk) = sessao
                .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &publica, &privada)
                .unwrap();
            let modulo = atributo(sessao, pubk, AttributeType::Modulus);
            let expoente = atributo(sessao, pubk, AttributeType::PublicExponent);
            (
                privk,
                der(0x30, &[inteiro(&modulo), inteiro(&expoente)].concat()),
            )
        }
    }

    fn gravar_certificado(sessao: &Session, id: &[u8], chave: &NoToken, nome: &str, ac: bool) {
        let mut parametros = CertificateParams::default();
        // Sem a feature `crypto`, o rcgen não sorteia o número de série.
        parametros.serial_number =
            Some(SerialNumber::from_slice(&[[0x01].as_slice(), id].concat()));
        parametros.distinguished_name.push(DnType::CommonName, nome);
        if ac {
            parametros.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let certificado = parametros.self_signed(chave).unwrap();
        let der = certificado.der().to_vec();
        let (_, lido) =
            <x509_parser::certificate::X509Certificate as x509_parser::prelude::FromDer<_>>::from_der(
                &der,
            )
            .unwrap();
        sessao
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Id(id.to_vec()),
                Attribute::Label(nome.as_bytes().to_vec()),
                Attribute::Subject(lido.subject().as_raw().to_vec()),
                Attribute::Value(der),
            ])
            .unwrap();
    }

    /// Inicializa um token vazio e devolve a sessão de usuário e a série.
    fn novo_token(contexto: &Pkcs11, rotulo: &str) -> (Session, String) {
        let livre = contexto
            .get_all_slots()
            .unwrap()
            .into_iter()
            .find(|s| !contexto.get_token_info(*s).unwrap().token_initialized())
            .expect("o SoftHSM sempre tem um slot livre");
        contexto
            .init_token(livre, &AuthPin::from(PIN_SO), rotulo)
            .unwrap();
        // O SoftHSM renumera o slot de um token inicializado.
        let slot = contexto
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|s| contexto.get_token_info(*s).unwrap().label() == rotulo)
            .unwrap();
        let serie = contexto
            .get_token_info(slot)
            .unwrap()
            .serial_number()
            .trim()
            .to_owned();
        let sessao = contexto.open_rw_session(slot).unwrap();
        sessao
            .login(UserType::So, Some(&AuthPin::from(PIN_SO)))
            .unwrap();
        sessao.init_pin(&AuthPin::from(PIN)).unwrap();
        sessao.logout().unwrap();
        sessao
            .login(UserType::User, Some(&AuthPin::from(PIN)))
            .unwrap();
        (sessao, serie)
    }

    fn chave_com_certificado(sessao: &Session, id: &[u8], ec: bool, nome: &str, ac: bool) {
        let (privada, publica) = gerar(sessao, id, ec);
        let chave = NoToken {
            sessao,
            privada,
            publica,
            ec,
        };
        gravar_certificado(sessao, id, &chave, nome, ac);
        if ac {
            // A chave da AC não fica no token: só o certificado.
            sessao.destroy_object(privada).unwrap();
            for publica in sessao
                .find_objects(&[
                    Attribute::Class(ObjectClass::PUBLIC_KEY),
                    Attribute::KeyType(KeyType::RSA),
                    Attribute::Id(id.to_vec()),
                ])
                .unwrap()
            {
                sessao.destroy_object(publica).unwrap();
            }
        }
    }

    pub fn preparar(modulo: &std::path::Path) -> (String, String) {
        let contexto = Pkcs11::new(modulo).unwrap();
        contexto
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();
        let (a, serie_a) = novo_token(&contexto, "gd-burti-a");
        chave_com_certificado(&a, ID_RSA, false, "FULANO DE TAL:00000000000", false);
        chave_com_certificado(&a, ID_EC, true, "FULANO DE TAL:00000000000", false);
        chave_com_certificado(&a, ID_DA_AC, false, "AC Teste", true);
        drop(a);
        let (b, serie_b) = novo_token(&contexto, "gd-burti-b");
        chave_com_certificado(&b, ID_RSA_B, false, "BELTRANO:11111111111", false);
        drop(b);
        (serie_a, serie_b)
    }
}
