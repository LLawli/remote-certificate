//! Os objetos de cada token e seus atributos (portado do RemoteID-linux).
//!
//! Um objeto Cryptoki é um saco de pares (tipo, bytes). Cada valor fica já
//! serializado, para que `C_GetAttributeValue` seja só uma cópia.

use cryptoki_sys::*;
use rsa::PublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{self, Decode, Encode};
use x509_cert::name::Name;

pub type Atributo = (CK_ATTRIBUTE_TYPE, Vec<u8>);

pub struct Objeto {
    pub handle: CK_OBJECT_HANDLE,
    pub atributos: Vec<Atributo>,
}

/// O OID do `commonName`.
const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
/// Quantos bytes do SHA-256 do SPKI viram o `CKA_ID`.
const BYTES_ID: usize = 20;

/// Os campos de um certificado, em DER, como o Cryptoki os quer.
pub struct Campos {
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    /// O DER do INTEGER, não o número em texto: o NSS compara byte a byte com
    /// o que extrai do certificado, e texto aqui faz o par certificado e chave
    /// nunca casar.
    pub serial: Vec<u8>,
    /// O que pareia o certificado com a chave. Sai do SPKI para não depender
    /// de o certificado trazer o SubjectKeyIdentifier.
    pub id: Vec<u8>,
    pub nome: Option<String>,
    /// `None` quando a chave não é RSA.
    pub publica: Option<PublicKey>,
}

pub fn ler_certificado(der: &[u8]) -> Result<Campos, String> {
    let certificado = Certificate::from_der(der).map_err(|e| format!("X.509 inválido: {e}"))?;
    let tbs = certificado.tbs_certificate();
    let codificar = |campo: &str, r: der::Result<Vec<u8>>| r.map_err(|e| format!("{campo}: {e}"));
    let spki = codificar("SPKI", tbs.subject_public_key_info().to_der())?;
    Ok(Campos {
        subject: codificar("subject", tbs.subject().to_der())?,
        issuer: codificar("issuer", tbs.issuer().to_der())?,
        serial: codificar("serial", tbs.serial_number().to_der())?,
        id: Sha256::digest(&spki)[..BYTES_ID].to_vec(),
        nome: nome_comum(tbs.subject()),
        publica: PublicKey::from_pkcs1_der(
            tbs.subject_public_key_info().subject_public_key.raw_bytes(),
        )
        .ok(),
    })
}

/// O `CN` do RDN mais específico, que no certificado do titular é o nome e o
/// CPF (`FULANO DE TAL:12345678901`).
fn nome_comum(nome: &Name) -> Option<String> {
    let atributos: Vec<_> = nome.iter().collect();
    atributos
        .into_iter()
        .rev()
        .find(|atributo| atributo.oid == CN)
        .and_then(|atributo| std::str::from_utf8(atributo.value.value()).ok())
        .filter(|cn| !cn.is_empty())
        .map(str::to_string)
}

fn booleano(v: bool) -> Vec<u8> {
    vec![if v { CK_TRUE } else { CK_FALSE }]
}

/// Os inteiros do Cryptoki vão no tamanho e na ordem de bytes nativos, que é
/// como o hospedeiro os lê de volta.
pub fn ulong(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// O que todo objeto destes tokens tem: é de leitura, e nada nele é privado.
/// O certificado e a chave aparecem antes do `C_Login`, como num token físico;
/// o login é o que libera a assinatura.
fn comuns(classe: CK_OBJECT_CLASS, rotulo: &str, id: &[u8]) -> Vec<Atributo> {
    vec![
        (CKA_CLASS, ulong(classe)),
        (CKA_TOKEN, booleano(true)),
        (CKA_PRIVATE, booleano(false)),
        (CKA_MODIFIABLE, booleano(false)),
        (CKA_LABEL, rotulo.as_bytes().to_vec()),
        (CKA_ID, id.to_vec()),
    ]
}

/// O que as duas chaves têm igual: RSA, gerada fora daqui, e sem derivação.
fn de_chave() -> [Atributo; 3] {
    [
        (CKA_KEY_TYPE, ulong(CKK_RSA)),
        (CKA_LOCAL, booleano(false)),
        (CKA_DERIVE, booleano(false)),
    ]
}

impl Objeto {
    /// O `CKO_CERTIFICATE` X.509 do titular. `CKA_TRUSTED` é falso: confiar é
    /// decisão do hospedeiro.
    pub fn certificado(
        handle: CK_OBJECT_HANDLE,
        der: &[u8],
        campos: &Campos,
        rotulo: &str,
    ) -> Objeto {
        let mut atributos = comuns(CKO_CERTIFICATE, rotulo, &campos.id);
        atributos.extend([
            (CKA_CERTIFICATE_TYPE, ulong(CKC_X_509)),
            (CKA_TRUSTED, booleano(false)),
            (
                CKA_CERTIFICATE_CATEGORY,
                ulong(CK_CERTIFICATE_CATEGORY_TOKEN_USER),
            ),
            (CKA_SUBJECT, campos.subject.clone()),
            (CKA_ISSUER, campos.issuer.clone()),
            (CKA_SERIAL_NUMBER, campos.serial.clone()),
            (CKA_VALUE, der.to_vec()),
        ]);
        Objeto { handle, atributos }
    }

    /// O `CKO_PUBLIC_KEY` do certificado. Redundante com o SPKI, mas o
    /// `p11tool --test-sign` e caminhos do GnuTLS o procuram.
    ///
    /// `CKA_ENCRYPT` acompanha o `CKF_ENCRYPT` do `CKM_RSA_PKCS`: ver
    /// `C_GetMechanismInfo`.
    pub fn chave_publica(
        handle: CK_OBJECT_HANDLE,
        campos: &Campos,
        rotulo: &str,
        modulo: &[u8],
        expoente: &[u8],
    ) -> Objeto {
        let mut atributos = comuns(CKO_PUBLIC_KEY, rotulo, &campos.id);
        atributos.extend(de_chave());
        atributos.extend([
            (CKA_VERIFY, booleano(true)),
            (CKA_VERIFY_RECOVER, booleano(false)),
            (CKA_ENCRYPT, booleano(true)),
            (CKA_WRAP, booleano(false)),
            (CKA_MODULUS_BITS, ulong(modulo.len() as CK_ULONG * 8)),
            (CKA_MODULUS, modulo.to_vec()),
            (CKA_PUBLIC_EXPONENT, expoente.to_vec()),
        ]);
        Objeto { handle, atributos }
    }

    /// O `CKO_PRIVATE_KEY`: o cabo que o hospedeiro segura para assinar. A
    /// chave de verdade está no token do servidor.
    ///
    /// - `CKA_ID` e `CKA_LABEL` iguais aos do certificado: é assim que o NSS e
    ///   o poppler pareiam os dois.
    /// - Módulo e expoente vêm do certificado, para o par fechar byte a byte.
    /// - Sensível e não extraível, como num token de verdade.
    /// - `CKA_ALWAYS_AUTHENTICATE` falso: o PIN pessoal entra uma vez pelo
    ///   `C_Login`, e o OTP, pela janela do agente.
    pub fn chave_privada(
        handle: CK_OBJECT_HANDLE,
        campos: &Campos,
        rotulo: &str,
        modulo: &[u8],
        expoente: &[u8],
    ) -> Objeto {
        let mut atributos = comuns(CKO_PRIVATE_KEY, rotulo, &campos.id);
        atributos.extend(de_chave());
        atributos.extend([
            (CKA_SENSITIVE, booleano(true)),
            (CKA_ALWAYS_SENSITIVE, booleano(true)),
            (CKA_EXTRACTABLE, booleano(false)),
            (CKA_NEVER_EXTRACTABLE, booleano(true)),
            (CKA_UNWRAP, booleano(false)),
            (CKA_ALWAYS_AUTHENTICATE, booleano(false)),
            (CKA_SIGN, booleano(true)),
            (CKA_SIGN_RECOVER, booleano(false)),
            (CKA_DECRYPT, booleano(false)),
            (CKA_MODULUS, modulo.to_vec()),
            (CKA_PUBLIC_EXPONENT, expoente.to_vec()),
        ]);
        Objeto { handle, atributos }
    }

    pub fn atributo(&self, tipo: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        self.atributos
            .iter()
            .find(|(t, _)| *t == tipo)
            .map(|(_, v)| v.as_slice())
    }

    pub fn classe(&self) -> Option<CK_OBJECT_CLASS> {
        Some(CK_OBJECT_CLASS::from_ne_bytes(
            self.atributo(CKA_CLASS)?.try_into().ok()?,
        ))
    }

    /// Os atributos de chave privada RSA que a especificação marca como
    /// sensíveis. Ler um deles é `CKR_ATTRIBUTE_SENSITIVE`, não "não existe".
    pub fn e_sensivel(&self, tipo: CK_ATTRIBUTE_TYPE) -> bool {
        self.classe() == Some(CKO_PRIVATE_KEY)
            && matches!(
                tipo,
                CKA_VALUE
                    | CKA_PRIVATE_EXPONENT
                    | CKA_PRIME_1
                    | CKA_PRIME_2
                    | CKA_EXPONENT_1
                    | CKA_EXPONENT_2
                    | CKA_COEFFICIENT
            )
    }

    /// A regra do `C_FindObjects`: todo atributo do gabarito tem de existir no
    /// objeto e bater byte a byte. Gabarito vazio casa com tudo.
    pub fn casa(&self, gabarito: &[Atributo]) -> bool {
        gabarito
            .iter()
            .all(|(tipo, valor)| self.atributo(*tipo) == Some(valor.as_slice()))
    }
}
