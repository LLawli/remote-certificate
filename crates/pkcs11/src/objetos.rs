//! Os objetos de cada token e seus atributos (portado do RemoteID-linux).
//!
//! Um objeto Cryptoki é um saco de pares (tipo, bytes). Cada valor fica já
//! serializado, para que `C_GetAttributeValue` seja só uma cópia.

use cryptoki_sys::*;
use rsa::PublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::{self, Decode, Encode};
use x509_cert::name::Name;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

pub type Atributo = (CK_ATTRIBUTE_TYPE, Vec<u8>);

pub struct Objeto {
    pub handle: CK_OBJECT_HANDLE,
    pub atributos: Vec<Atributo>,
}

/// O OID do `commonName`.
const CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// O algoritmo `id-ecPublicKey` do SPKI de uma chave EC (RFC 5480).
const EC_PUBLICA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// Uma curva com nome, a única forma de parâmetro EC que a face mostra.
#[derive(Debug, PartialEq)]
pub struct Curva {
    pub oid: ObjectIdentifier,
    /// O tamanho da chave para o `C_GetMechanismInfo`.
    pub bits: CK_ULONG,
    /// O tamanho da ordem: cada metade do `r‖s` de uma assinatura.
    pub bytes: usize,
}

/// As curvas NIST que o TLS usa e as Brainpool que a ICP-Brasil admite.
pub const CURVAS: [Curva; 6] = [
    curva("1.2.840.10045.3.1.7", 256, 32),   // P-256
    curva("1.3.132.0.34", 384, 48),          // P-384
    curva("1.3.132.0.35", 521, 66),          // P-521
    curva("1.3.36.3.3.2.8.1.1.7", 256, 32),  // brainpoolP256r1
    curva("1.3.36.3.3.2.8.1.1.11", 384, 48), // brainpoolP384r1
    curva("1.3.36.3.3.2.8.1.1.13", 512, 64), // brainpoolP512r1
];

const fn curva(oid: &str, bits: CK_ULONG, bytes: usize) -> Curva {
    Curva {
        oid: ObjectIdentifier::new_unwrap(oid),
        bits,
        bytes,
    }
}

/// A chave pública do certificado, no que a face precisa dela.
#[derive(Debug, Clone)]
pub enum Publica {
    Rsa(PublicKey),
    Ec {
        curva: &'static Curva,
        /// O `CKA_EC_PARAMS`: o OID da curva, em DER.
        parametros: Vec<u8>,
        /// O `CKA_EC_POINT`: o ponto do SPKI dentro de um OCTET STRING, em
        /// DER, como a especificação 2.40 manda.
        ponto: Vec<u8>,
    },
}

impl Publica {
    fn do_spki(spki: &SubjectPublicKeyInfoOwned) -> Option<Publica> {
        let bits = spki.subject_public_key.raw_bytes();
        if spki.algorithm.oid != EC_PUBLICA {
            return PublicKey::from_pkcs1_der(bits).ok().map(Publica::Rsa);
        }
        let oid: ObjectIdentifier = spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
        let curva = CURVAS.iter().find(|c| c.oid == oid)?;
        Some(Publica::Ec {
            curva,
            parametros: oid.to_der().ok()?,
            ponto: OctetString::new(bits).ok()?.to_der().ok()?,
        })
    }

    /// O tamanho de toda assinatura: o do módulo no RSA, o `r‖s` no EC.
    pub fn bytes_da_assinatura(&self) -> usize {
        match self {
            Publica::Rsa(publica) => rsa::traits::PublicKeyParts::size(publica),
            Publica::Ec { curva, .. } => 2 * curva.bytes,
        }
    }

    /// O tamanho da chave, em bits, como o `C_GetMechanismInfo` o mostra.
    pub fn bits(&self) -> CK_ULONG {
        match self {
            Publica::Rsa(publica) => rsa::traits::PublicKeyParts::size(publica) as CK_ULONG * 8,
            Publica::Ec { curva, .. } => curva.bits,
        }
    }
}
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
    /// `None` quando a chave não é RSA nem EC de uma curva conhecida.
    pub publica: Option<Publica>,
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
        publica: Publica::do_spki(tbs.subject_public_key_info()),
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

/// O que as duas chaves têm igual: o tipo, gerada fora daqui, sem derivação,
/// e os números públicos (módulo e expoente no RSA, a curva no EC). O ponto
/// EC fica só na pública, que é onde o NSS e o OpenSSL o procuram.
fn de_chave(publica: &Publica) -> Vec<Atributo> {
    let mut atributos = vec![(CKA_LOCAL, booleano(false)), (CKA_DERIVE, booleano(false))];
    match publica {
        Publica::Rsa(chave) => {
            use rsa::traits::PublicKeyParts;
            // `to_be_bytes_trimmed_vartime` tira os zeros à esquerda, como o
            // Cryptoki manda.
            atributos.extend([
                (CKA_KEY_TYPE, ulong(CKK_RSA)),
                (
                    CKA_MODULUS,
                    chave.n().to_be_bytes_trimmed_vartime().to_vec(),
                ),
                (
                    CKA_PUBLIC_EXPONENT,
                    chave.e().to_be_bytes_trimmed_vartime().to_vec(),
                ),
            ]);
        }
        Publica::Ec { parametros, .. } => {
            atributos.extend([
                (CKA_KEY_TYPE, ulong(CKK_EC)),
                (CKA_EC_PARAMS, parametros.clone()),
            ]);
        }
    }
    atributos
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
    /// `C_GetMechanismInfo`. Uma chave EC não cifra.
    pub fn chave_publica(
        handle: CK_OBJECT_HANDLE,
        campos: &Campos,
        rotulo: &str,
        publica: &Publica,
    ) -> Objeto {
        let mut atributos = comuns(CKO_PUBLIC_KEY, rotulo, &campos.id);
        atributos.extend(de_chave(publica));
        let rsa = matches!(publica, Publica::Rsa(_));
        atributos.extend([
            (CKA_VERIFY, booleano(true)),
            (CKA_VERIFY_RECOVER, booleano(false)),
            (CKA_ENCRYPT, booleano(rsa)),
            (CKA_WRAP, booleano(false)),
        ]);
        match publica {
            Publica::Rsa(_) => atributos.push((CKA_MODULUS_BITS, ulong(publica.bits()))),
            Publica::Ec { ponto, .. } => atributos.push((CKA_EC_POINT, ponto.clone())),
        }
        Objeto { handle, atributos }
    }

    /// O `CKO_PRIVATE_KEY`: o cabo que o hospedeiro segura para assinar. A
    /// chave de verdade está no token do servidor.
    ///
    /// - `CKA_ID` e `CKA_LABEL` iguais aos do certificado: é assim que o NSS e
    ///   o poppler pareiam os dois.
    /// - Módulo e expoente (ou a curva) vêm do certificado, para o par fechar
    ///   byte a byte.
    /// - Sensível e não extraível, como num token de verdade.
    /// - `CKA_ALWAYS_AUTHENTICATE` falso: o PIN pessoal entra uma vez pelo
    ///   `C_Login`, e o OTP, pela janela do agente.
    pub fn chave_privada(
        handle: CK_OBJECT_HANDLE,
        campos: &Campos,
        rotulo: &str,
        publica: &Publica,
    ) -> Objeto {
        let mut atributos = comuns(CKO_PRIVATE_KEY, rotulo, &campos.id);
        atributos.extend(de_chave(publica));
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

    /// Os atributos de chave privada que a especificação marca como
    /// sensíveis (no EC, o `CKA_VALUE`). Ler um deles é `CKR_ATTRIBUTE_SENSITIVE`, não "não existe".
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
