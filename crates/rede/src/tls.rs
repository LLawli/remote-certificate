//! mTLS 1.3 sem autoridade certificadora: cada lado tem um certificado
//! autoassinado, e o que vale é a chave P-256 dentro dele. O servidor confere a
//! do cliente contra os dispositivos pareados; o cliente confere a do servidor
//! contra a que fixou no pareamento.

use std::fmt;
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use zeroize::Zeroizing;

/// O começo de todo SubjectPublicKeyInfo de uma chave P-256 em DER: o
/// algoritmo (`id-ecPublicKey`, `prime256v1`) e o cabeçalho do ponto.
const SPKI_P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// O prefixo e o ponto não comprimido (65 bytes).
const TAMANHO_DO_SPKI_P256: usize = SPKI_P256.len() + 65;
/// O nome que o cliente manda no SNI. Ninguém o confere: vale a chave.
const NOME_DO_SERVIDOR: &str = "remote-certificate";

pub type Impressao = [u8; 32];

/// O SHA-256 do SubjectPublicKeyInfo em DER.
pub fn impressao(chave_publica: &[u8]) -> Impressao {
    Sha256::digest(chave_publica).into()
}

/// O SubjectPublicKeyInfo do certificado, se for uma chave P-256.
pub fn chave_publica(certificado: &[u8]) -> Option<Vec<u8>> {
    let certificado = Certificate::from_der(certificado).ok()?;
    let spki = certificado
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .ok()?;
    (spki.len() == TAMANHO_DO_SPKI_P256 && spki.starts_with(&SPKI_P256)).then_some(spki)
}

/// O par de chaves P-256 de um lado da conexão e o certificado autoassinado
/// dele.
pub struct Identidade {
    certificado: Vec<u8>,
    /// PKCS#8 em DER.
    chave: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Identidade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identidade")
            .field(
                "impressao",
                &data_encoding::HEXLOWER.encode(&self.impressao()),
            )
            .finish_non_exhaustive()
    }
}

impl Identidade {
    pub fn gerar() -> Result<Identidade, rcgen::Error> {
        let par = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut parametros = CertificateParams::new(Vec::<String>::new())?;
        let mut nome = DistinguishedName::new();
        nome.push(DnType::CommonName, NOME_DO_SERVIDOR);
        parametros.distinguished_name = nome;
        // A validade não é conferida por ninguém: só a chave conta.
        parametros.not_before = rcgen::date_time_ymd(2000, 1, 1);
        parametros.not_after = rcgen::date_time_ymd(9999, 12, 31);
        let certificado = parametros.self_signed(&par)?;
        Ok(Identidade {
            certificado: certificado.der().to_vec(),
            chave: Zeroizing::new(par.serialize_der()),
        })
    }

    /// Uma identidade guardada. `None` se o certificado não é de uma chave
    /// P-256.
    pub fn de(certificado: Vec<u8>, chave: Zeroizing<Vec<u8>>) -> Option<Identidade> {
        chave_publica(&certificado)?;
        Some(Identidade { certificado, chave })
    }

    pub fn certificado(&self) -> &[u8] {
        &self.certificado
    }

    pub fn chave_pkcs8(&self) -> &[u8] {
        &self.chave
    }

    pub fn chave_publica(&self) -> Vec<u8> {
        chave_publica(&self.certificado).expect("conferida ao criar")
    }

    pub fn impressao(&self) -> Impressao {
        impressao(&self.chave_publica())
    }

    fn para_o_rustls(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![CertificateDer::from(self.certificado.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.chave.to_vec())),
        )
    }
}

/// O que o servidor sabe das chaves de quem conecta.
pub trait Porteiro: Send + Sync + fmt::Debug {
    /// Se a chave é de um dispositivo pareado, ou se há um pareamento
    /// esperando uma chave nova.
    fn deixa_entrar(&self, chave_publica: &[u8]) -> bool;
}

/// A chave do servidor que o cliente aceita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixacao {
    /// O começo da impressão, vindo do código de pareamento.
    Pareamento([u8; 16]),
    /// A impressão inteira, guardada depois do pareamento.
    Completa(Impressao),
}

impl Fixacao {
    fn confere(&self, chave_publica: &[u8]) -> bool {
        let vista = impressao(chave_publica);
        match self {
            Fixacao::Pareamento(comeco) => vista.starts_with(comeco),
            Fixacao::Completa(inteira) => vista == *inteira,
        }
    }
}

fn provedor() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

const ESQUEMAS: [SignatureScheme; 1] = [SignatureScheme::ECDSA_NISTP256_SHA256];

/// A assinatura do handshake, só com a chave P-256 do certificado.
fn conferir_assinatura(
    provedor: &CryptoProvider,
    mensagem: &[u8],
    certificado: &CertificateDer<'_>,
    assinatura: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if !ESQUEMAS.contains(&assinatura.scheme) || chave_publica(certificado).is_none() {
        return Err(Error::InvalidCertificate(CertificateError::BadSignature));
    }
    verify_tls13_signature(
        mensagem,
        certificado,
        assinatura,
        &provedor.signature_verification_algorithms,
    )
}

fn so_tls13() -> Error {
    Error::General("só TLS 1.3".into())
}

fn chave_recusada() -> Error {
    Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

#[derive(Debug)]
struct VerificadorDoCliente {
    porteiro: Arc<dyn Porteiro>,
    provedor: Arc<CryptoProvider>,
}

impl ClientCertVerifier for VerificadorDoCliente {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        certificado: &CertificateDer<'_>,
        _intermediarios: &[CertificateDer<'_>],
        _agora: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        match chave_publica(certificado) {
            Some(chave) if self.porteiro.deixa_entrar(&chave) => {
                Ok(ClientCertVerified::assertion())
            }
            _ => Err(chave_recusada()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(so_tls13())
    }

    fn verify_tls13_signature(
        &self,
        mensagem: &[u8],
        certificado: &CertificateDer<'_>,
        assinatura: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        conferir_assinatura(&self.provedor, mensagem, certificado, assinatura)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ESQUEMAS.to_vec()
    }
}

#[derive(Debug)]
struct VerificadorDoServidor {
    fixacao: Fixacao,
    provedor: Arc<CryptoProvider>,
}

impl ServerCertVerifier for VerificadorDoServidor {
    fn verify_server_cert(
        &self,
        certificado: &CertificateDer<'_>,
        _intermediarios: &[CertificateDer<'_>],
        _nome: &ServerName<'_>,
        _ocsp: &[u8],
        _agora: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match chave_publica(certificado) {
            Some(chave) if self.fixacao.confere(&chave) => Ok(ServerCertVerified::assertion()),
            _ => Err(chave_recusada()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(so_tls13())
    }

    fn verify_tls13_signature(
        &self,
        mensagem: &[u8],
        certificado: &CertificateDer<'_>,
        assinatura: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        conferir_assinatura(&self.provedor, mensagem, certificado, assinatura)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ESQUEMAS.to_vec()
    }
}

pub fn config_do_servidor(
    identidade: &Identidade,
    porteiro: Arc<dyn Porteiro>,
) -> Result<ServerConfig, Error> {
    let provedor = provedor();
    let (certificados, chave) = identidade.para_o_rustls();
    ServerConfig::builder_with_provider(provedor.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(VerificadorDoCliente { porteiro, provedor }))
        .with_single_cert(certificados, chave)
}

pub fn config_do_cliente(identidade: &Identidade, fixacao: Fixacao) -> Result<ClientConfig, Error> {
    let provedor = provedor();
    let (certificados, chave) = identidade.para_o_rustls();
    ClientConfig::builder_with_provider(provedor.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(VerificadorDoServidor { fixacao, provedor }))
        .with_client_auth_cert(certificados, chave)
}

/// O nome que vai no SNI.
pub fn nome_do_servidor() -> ServerName<'static> {
    ServerName::try_from(NOME_DO_SERVIDOR).expect("nome DNS válido")
}

/// Se uma falha de conexão é a chave do outro lado recusada no handshake.
pub fn e_chave_recusada(erro: &std::io::Error) -> bool {
    erro.get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .is_some_and(|e| *e == chave_recusada())
}

/// Se o outro lado recusou a nossa chave. No TLS 1.3 o cliente só fica sabendo
/// na primeira leitura, pelo alerta, então a falha chega por qualquer camada
/// acima (o HTTP, por exemplo).
pub fn recusaram_a_nossa_chave(erro: &(dyn std::error::Error + 'static)) -> bool {
    let mut atual = Some(erro);
    while let Some(e) = atual {
        if let Some(Error::AlertReceived(AlertDescription::AccessDenied)) = e.downcast_ref() {
            return true;
        }
        // O `source()` de um io::Error pula o erro de dentro: ele vem pelo
        // `get_ref()`.
        atual = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|dentro| dentro as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    false
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_identidade_gerada_e_p256_e_volta_igual() {
        let gerada = Identidade::gerar().unwrap();
        assert_eq!(gerada.chave_publica().len(), TAMANHO_DO_SPKI_P256);
        let de_volta = Identidade::de(
            gerada.certificado().to_vec(),
            Zeroizing::new(gerada.chave_pkcs8().to_vec()),
        )
        .unwrap();
        assert_eq!(de_volta.impressao(), gerada.impressao());
        assert_ne!(Identidade::gerar().unwrap().impressao(), gerada.impressao());
    }

    #[test]
    fn so_chave_p256_vale() {
        let ed25519 = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let certificado = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&ed25519)
            .unwrap();
        assert_eq!(chave_publica(certificado.der()), None);
        assert_eq!(chave_publica(b"lixo"), None);
    }

    #[test]
    fn a_fixacao_do_pareamento_confere_o_comeco_e_a_completa_tudo() {
        let chave = Identidade::gerar().unwrap().chave_publica();
        let inteira = impressao(&chave);
        let comeco: [u8; 16] = inteira[..16].try_into().unwrap();
        assert!(Fixacao::Pareamento(comeco).confere(&chave));
        assert!(Fixacao::Completa(inteira).confere(&chave));
        let outra = Identidade::gerar().unwrap().chave_publica();
        assert!(!Fixacao::Pareamento(comeco).confere(&outra));
        assert!(!Fixacao::Completa(inteira).confere(&outra));
    }
}
