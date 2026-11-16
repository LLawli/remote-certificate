//! O token, pelo módulo PKCS#11 do SafeSign (`libaetpkss.so`).
//!
//! As manias que ficam aqui, e não no contrato:
//!
//! - As chaves privadas do SafeSign são objetos privados: sem login, o token só
//!   mostra os certificados. O `listar` parte dos certificados (que não pedem
//!   PIN) e liga cada um à chave pelo `CKA_ID`.
//! - O token guarda também os certificados das ACs da cadeia; um certificado
//!   de AC não tem chave privada no token e fica de fora.
//! - Cada assinatura abre uma sessão, entra, assina e sai: um token removido e
//!   recolocado não deixa uma sessão velha para trás.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as ErroPkcs11, RvError};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use protocolo::{Chave, Erro, Mecanismo, Segredo, TipoDeErro};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::erro::{erro, traduzir};
use crate::mecanismos::{TipoDeChave, candidatos, chamada};

/// O que a conversa precisa do token. O driver de verdade é [`SafeSign`]; os
/// testes da conversa usam um token falso.
pub trait Token {
    /// Confere o PIN no token de série `serie` (ou no único conectado, sem
    /// série) e devolve a série dele.
    fn configurar(&mut self, serie: Option<&str>, pin: &Segredo) -> Result<String, Erro>;
    fn listar(&mut self, serie: &str) -> Result<Vec<Chave>, Erro>;
    /// Tudo o que dá para conferir antes de pedir o PIN: o token está lá, não
    /// travou, tem a chave, e a chave assina com o mecanismo.
    fn conferir(
        &mut self,
        serie: &str,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
    ) -> Result<(), Erro>;
    fn assinar(
        &mut self,
        serie: &str,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
        pin: &Segredo,
    ) -> Result<Vec<u8>, Erro>;
}

pub struct SafeSign {
    modulo: PathBuf,
    contexto: Option<Pkcs11>,
}

impl SafeSign {
    pub fn novo(modulo: impl Into<PathBuf>) -> Self {
        Self {
            modulo: modulo.into(),
            contexto: None,
        }
    }

    /// Carrega o módulo no primeiro uso: sem ele, o driver ainda se apresenta,
    /// e cada operação diz por que não carregou.
    fn contexto(&mut self) -> Result<&Pkcs11, Erro> {
        if self.contexto.is_none() {
            let contexto =
                Pkcs11::new(&self.modulo).map_err(|e| traduzir("carregar o módulo", e))?;
            contexto
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| traduzir("C_Initialize", e))?;
            eprintln!("gd-burti: módulo {} carregado", self.modulo.display());
            self.contexto = Some(contexto);
        }
        Ok(self.contexto.as_ref().expect("carregado acima"))
    }
}

/// Os tokens conectados, com a série de cada um.
fn tokens(contexto: &Pkcs11) -> Result<Vec<(Slot, String)>, Erro> {
    let slots = contexto.get_slots_with_token().map_err(|e| match e {
        // Sem leitor no PC/SC (ou sem o pcscd), o SafeSign não devolve uma
        // lista vazia: falha com CKR_FUNCTION_FAILED. Para o servidor, é o
        // token que não está lá.
        ErroPkcs11::Pkcs11(RvError::FunctionFailed, _) => erro(
            TipoDeErro::TokenAusente,
            "O SafeSign não encontrou leitor nenhum no PC/SC (C_GetSlotList devolveu \
             FunctionFailed): confira o pcscd e o token",
        ),
        e => traduzir("C_GetSlotList", e),
    })?;
    let mut tokens = Vec::new();
    for slot in slots {
        match contexto.get_token_info(slot) {
            Ok(info) => tokens.push((slot, info.serial_number().trim().to_owned())),
            // Removido entre a lista e a pergunta: é como se não estivesse.
            Err(ErroPkcs11::Pkcs11(RvError::TokenNotPresent, _)) => {}
            Err(e) => return Err(traduzir("C_GetTokenInfo", e)),
        }
    }
    Ok(tokens)
}

fn slot_da_serie(contexto: &Pkcs11, serie: &str) -> Result<Slot, Erro> {
    tokens(contexto)?
        .into_iter()
        .find(|(_, s)| s == serie)
        .map(|(slot, _)| slot)
        .ok_or_else(|| {
            erro(
                TipoDeErro::TokenAusente,
                format!("O token GD Burti de série {serie} não está conectado"),
            )
        })
}

/// Recusa antes de gastar uma tentativa do PIN num token que já travou.
fn conferir_pin_livre(contexto: &Pkcs11, slot: Slot) -> Result<(), Erro> {
    let info = contexto
        .get_token_info(slot)
        .map_err(|e| traduzir("C_GetTokenInfo", e))?;
    if info.user_pin_locked() {
        return Err(erro(
            TipoDeErro::Bloqueado,
            "O PIN do token está bloqueado; desbloqueie no Token Administration",
        ));
    }
    if !info.user_pin_initialized() {
        return Err(erro(
            TipoDeErro::Outro,
            "O token não tem PIN de usuário; inicialize no Token Administration",
        ));
    }
    Ok(())
}

fn entrar(sessao: &Session, pin: &Segredo) -> Result<(), Erro> {
    let pin = AuthPin::from(pin.expor());
    match sessao.login(UserType::User, Some(&pin)) {
        Ok(()) | Err(ErroPkcs11::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(e) => Err(traduzir("C_Login", e)),
    }
}

/// Os mecanismos do contrato que o token diz que assina.
fn mecanismos_do_token(contexto: &Pkcs11, slot: Slot) -> Result<Vec<MechanismType>, Erro> {
    let lista = contexto
        .get_mechanism_list(slot)
        .map_err(|e| traduzir("C_GetMechanismList", e))?;
    Ok(lista
        .into_iter()
        .filter(|tipo| {
            // Um módulo que não sabe descrever o mecanismo fica com o benefício
            // da dúvida; um que diz que não assina com ele, não.
            contexto
                .get_mechanism_info(slot, *tipo)
                .map(|info| info.sign())
                .unwrap_or(true)
        })
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// O que interessa de um certificado do token.
#[derive(Debug, PartialEq, Eq)]
pub struct Lido {
    pub tipo: TipoDeChave,
    pub nome: Option<String>,
}

/// O tipo da chave e o nome do titular, ou `None` para um certificado que não
/// é de uma chave de assinatura do titular (o de uma AC, ou uma chave DSA).
pub fn ler_certificado(der: &[u8]) -> Option<Lido> {
    let (_, certificado) = X509Certificate::from_der(der).ok()?;
    if certificado
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|b| b.value.ca)
    {
        return None;
    }
    let tipo = match certificado.public_key().parsed().ok()? {
        PublicKey::RSA(_) => TipoDeChave::Rsa,
        PublicKey::EC(_) => TipoDeChave::Ec,
        _ => return None,
    };
    let nome = certificado
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);
    Some(Lido { tipo, nome })
}

fn chaves(contexto: &Pkcs11, slot: Slot) -> Result<Vec<(Chave, TipoDeChave)>, Erro> {
    let do_token = mecanismos_do_token(contexto, slot)?;
    let sessao = contexto
        .open_ro_session(slot)
        .map_err(|e| traduzir("C_OpenSession", e))?;
    let certificados = sessao
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
        ])
        .map_err(|e| traduzir("C_FindObjects", e))?;
    let mut chaves: Vec<(Chave, TipoDeChave)> = Vec::new();
    for objeto in certificados {
        let atributos = sessao
            .get_attributes(
                objeto,
                &[
                    AttributeType::Id,
                    AttributeType::Value,
                    AttributeType::Label,
                ],
            )
            .map_err(|e| traduzir("C_GetAttributeValue", e))?;
        let (mut id, mut der, mut rotulo) = (Vec::new(), Vec::new(), String::new());
        for atributo in atributos {
            match atributo {
                Attribute::Id(v) => id = v,
                Attribute::Value(v) => der = v,
                Attribute::Label(v) => rotulo = String::from_utf8_lossy(&v).trim().to_owned(),
                _ => {}
            }
        }
        if id.is_empty() || der.is_empty() {
            continue;
        }
        let Some(lido) = ler_certificado(&der) else {
            continue;
        };
        let id = hex(&id);
        if chaves.iter().any(|(c, _)| c.id == id) {
            eprintln!("gd-burti: dois certificados com o CKA_ID {id}; fica o primeiro");
            continue;
        }
        let mecanismos: Vec<Mecanismo> = candidatos(lido.tipo)
            .iter()
            .filter(|(_, tipo)| do_token.contains(tipo))
            .map(|(m, _)| *m)
            .collect();
        if mecanismos.is_empty() {
            eprintln!("gd-burti: a chave {id} não assina com nenhum mecanismo do contrato");
            continue;
        }
        let rotulo = lido
            .nome
            .or((!rotulo.is_empty()).then_some(rotulo))
            .unwrap_or_else(|| id.clone());
        chaves.push((
            Chave {
                id,
                rotulo,
                certificado: der,
                mecanismos,
            },
            lido.tipo,
        ));
    }
    Ok(chaves)
}

fn id_da_chave(chave: &str) -> Result<Vec<u8>, Erro> {
    let ausente = || erro(TipoDeErro::ChaveAusente, format!("Não há a chave {chave}"));
    if chave.is_empty() || !chave.len().is_multiple_of(2) {
        return Err(ausente());
    }
    (0..chave.len())
        .step_by(2)
        .map(|i| {
            chave
                .get(i..i + 2)
                .and_then(|par| u8::from_str_radix(par, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(ausente)
}

impl Token for SafeSign {
    fn configurar(&mut self, serie: Option<&str>, pin: &Segredo) -> Result<String, Erro> {
        let contexto = self.contexto()?;
        let conectados = tokens(contexto)?;
        let (slot, serie) = match serie {
            Some(serie) => (slot_da_serie(contexto, serie)?, serie.to_owned()),
            None => match conectados.as_slice() {
                [] => {
                    return Err(erro(
                        TipoDeErro::TokenAusente,
                        "Nenhum token GD Burti conectado",
                    ));
                }
                [(slot, serie)] => (*slot, serie.clone()),
                varios => {
                    let series: Vec<&str> = varios.iter().map(|(_, s)| s.as_str()).collect();
                    return Err(erro(
                        TipoDeErro::PedidoInvalido,
                        format!(
                            "Há {} tokens conectados; informe a série de um deles: {}",
                            varios.len(),
                            series.join(", ")
                        ),
                    ));
                }
            },
        };
        conferir_pin_livre(contexto, slot)?;
        let sessao = contexto
            .open_ro_session(slot)
            .map_err(|e| traduzir("C_OpenSession", e))?;
        entrar(&sessao, pin)?;
        let _ = sessao.logout();
        Ok(serie)
    }

    fn listar(&mut self, serie: &str) -> Result<Vec<Chave>, Erro> {
        let contexto = self.contexto()?;
        let slot = slot_da_serie(contexto, serie)?;
        Ok(chaves(contexto, slot)?
            .into_iter()
            .map(|(c, _)| c)
            .collect())
    }

    fn conferir(
        &mut self,
        serie: &str,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
    ) -> Result<(), Erro> {
        chamada(mecanismo, dados.len())?;
        let contexto = self.contexto()?;
        let slot = slot_da_serie(contexto, serie)?;
        let (encontrada, _) = chaves(contexto, slot)?
            .into_iter()
            .find(|(c, _)| c.id == chave)
            .ok_or_else(|| erro(TipoDeErro::ChaveAusente, format!("Não há a chave {chave}")))?;
        if !encontrada.mecanismos.contains(&mecanismo) {
            return Err(erro(
                TipoDeErro::MecanismoNaoSuportado,
                "A chave não assina com esse mecanismo",
            ));
        }
        conferir_pin_livre(contexto, slot)
    }

    fn assinar(
        &mut self,
        serie: &str,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
        pin: &Segredo,
    ) -> Result<Vec<u8>, Erro> {
        let chamada = chamada(mecanismo, dados.len())?;
        let id = id_da_chave(chave)?;
        let contexto = self.contexto()?;
        let slot = slot_da_serie(contexto, serie)?;
        let sessao = contexto
            .open_ro_session(slot)
            .map_err(|e| traduzir("C_OpenSession", e))?;
        entrar(&sessao, pin)?;
        let resultado = (|| {
            let privada = sessao
                .find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Id(id),
                ])
                .map_err(|e| traduzir("C_FindObjects", e))?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    erro(
                        TipoDeErro::ChaveAusente,
                        format!("O token não tem a chave privada {chave}"),
                    )
                })?;
            sessao
                .sign(&chamada, privada, dados)
                .map_err(|e| traduzir("C_Sign", e))
        })();
        let _ = sessao.logout();
        resultado
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn id_da_chave_e_o_hex_do_cka_id() {
        assert_eq!(id_da_chave("f17c01").unwrap(), [0xf1, 0x7c, 0x01]);
        assert_eq!(hex(&[0xf1, 0x7c, 0x01]), "f17c01");
        for invalido in ["", "f", "zz", "f17ç"] {
            let falha = id_da_chave(invalido).unwrap_err();
            assert_eq!(falha.tipo, TipoDeErro::ChaveAusente, "{invalido}");
        }
    }

    #[test]
    fn lixo_nao_e_certificado() {
        assert_eq!(ler_certificado(b"isto nao e DER"), None);
    }
}
