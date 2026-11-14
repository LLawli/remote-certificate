//! Os slots: um por token do servidor, montados da listagem do agente.
//!
//! Os números de slot e de objeto ficam estáveis enquanto o módulo vive: o
//! mesmo token e a mesma chave voltam sempre com o mesmo número, mesmo que a
//! listagem mude a ordem ou um token suma e volte.

use std::collections::BTreeMap;

use cryptoki_sys::*;
use ipc::ChaveDoToken;
use protocolo::Mecanismo;
use rsa::PublicKey;
use rsa::traits::PublicKeyParts;

use crate::objetos::{Atributo, Objeto, ler_certificado};

/// Os mecanismos que a face expõe, e o nome de cada um no contrato. RSA-PSS
/// e ECDSA ficam de fora: o contrato não leva os parâmetros deles, e nenhum
/// driver aceito os declara.
pub const MECANISMOS: [(Mecanismo, CK_MECHANISM_TYPE); 4] = [
    (Mecanismo::RsaPkcs, CKM_RSA_PKCS),
    (Mecanismo::Sha256RsaPkcs, CKM_SHA256_RSA_PKCS),
    (Mecanismo::Sha384RsaPkcs, CKM_SHA384_RSA_PKCS),
    (Mecanismo::Sha512RsaPkcs, CKM_SHA512_RSA_PKCS),
];

pub fn do_contrato(tipo: CK_MECHANISM_TYPE) -> Option<Mecanismo> {
    MECANISMOS.iter().find(|(_, t)| *t == tipo).map(|(m, _)| *m)
}

/// Uma chave que assina: o par de objetos que aponta para ela.
pub struct Chave {
    /// O id da chave no token do servidor.
    pub id: String,
    pub mecanismos: Vec<CK_MECHANISM_TYPE>,
    pub publica: PublicKey,
    pub privada: CK_OBJECT_HANDLE,
    pub handle_publica: CK_OBJECT_HANDLE,
}

impl Chave {
    /// O tamanho de toda assinatura e cifra: o do módulo da chave.
    pub fn bytes(&self) -> usize {
        self.publica.size()
    }
}

pub struct Slot {
    pub id: CK_SLOT_ID,
    /// O nome do token no servidor. `None` é o slot que existe quando não há
    /// token nenhum (ver [`montar`]).
    pub token: Option<String>,
    pub chaves: Vec<Chave>,
    pub objetos: Vec<Objeto>,
}

impl Slot {
    pub fn objeto(&self, handle: CK_OBJECT_HANDLE) -> Option<&Objeto> {
        self.objetos.iter().find(|o| o.handle == handle)
    }

    pub fn buscar(&self, gabarito: &[Atributo]) -> Vec<CK_OBJECT_HANDLE> {
        self.objetos
            .iter()
            .filter(|o| o.casa(gabarito))
            .map(|o| o.handle)
            .collect()
    }

    pub fn da_privada(&self, handle: CK_OBJECT_HANDLE) -> Option<&Chave> {
        self.chaves.iter().find(|c| c.privada == handle)
    }

    pub fn da_publica(&self, handle: CK_OBJECT_HANDLE) -> Option<&Chave> {
        self.chaves.iter().find(|c| c.handle_publica == handle)
    }

    /// Os mecanismos de alguma chave deste slot, sem repetir.
    pub fn mecanismos(&self) -> Vec<CK_MECHANISM_TYPE> {
        MECANISMOS
            .iter()
            .map(|(_, t)| *t)
            .filter(|t| self.chaves.iter().any(|c| c.mecanismos.contains(t)))
            .collect()
    }

    /// O maior e o menor tamanho de chave, em bits, para `C_GetMechanismInfo`.
    pub fn bits(&self) -> (CK_ULONG, CK_ULONG) {
        let bits = self.chaves.iter().map(|c| c.bytes() as CK_ULONG * 8);
        (
            bits.clone().min().unwrap_or(2048),
            bits.max().unwrap_or(2048),
        )
    }
}

/// Os números já dados a slots e objetos.
#[derive(Default)]
pub struct Numeracao {
    slots: BTreeMap<Option<String>, CK_SLOT_ID>,
    objetos: BTreeMap<(String, String, u8), CK_OBJECT_HANDLE>,
}

impl Numeracao {
    fn slot(&mut self, token: Option<&str>) -> CK_SLOT_ID {
        // Diferente de zero: há software que trata `0` como "nenhum".
        let proximo = self.slots.len() as CK_SLOT_ID + 1;
        *self
            .slots
            .entry(token.map(str::to_string))
            .or_insert(proximo)
    }

    fn objeto(&mut self, token: &str, chave: &str, tipo: u8) -> CK_OBJECT_HANDLE {
        // Zero é `CK_INVALID_HANDLE`.
        let proximo = self.objetos.len() as CK_OBJECT_HANDLE + 1;
        *self
            .objetos
            .entry((token.to_string(), chave.to_string(), tipo))
            .or_insert(proximo)
    }
}

const CERTIFICADO: u8 = 0;
const PRIVADA: u8 = 1;
const PUBLICA: u8 = 2;

/// Os slots da listagem, na ordem em que os tokens aparecem.
///
/// Sem token nenhum (agente parado, computador não pareado, servidor sem
/// tokens), fica um slot com um token vazio. Um módulo sem token faz o
/// `C_GetSlotList(CK_TRUE)` devolver a lista vazia, e pelo RPC do p11-kit a
/// segunda passada com zero itens volta `CKR_BUFFER_TOO_SMALL`: quem repete
/// enquanto o buffer é pequeno (o crate `cryptoki`) fica em laço para sempre.
/// Medido no RemoteID-linux, com o p11-kit 0.26.
pub fn montar(listagem: &[ChaveDoToken], numeracao: &mut Numeracao) -> Vec<Slot> {
    let mut slots: Vec<Slot> = Vec::new();
    for item in listagem {
        let indice = match slots
            .iter()
            .position(|s| s.token.as_deref() == Some(&item.token))
        {
            Some(i) => i,
            None => {
                slots.push(Slot {
                    id: numeracao.slot(Some(&item.token)),
                    token: Some(item.token.clone()),
                    chaves: Vec::new(),
                    objetos: Vec::new(),
                });
                slots.len() - 1
            }
        };
        acrescentar(&mut slots[indice], item, numeracao);
    }
    if slots.is_empty() {
        slots.push(Slot {
            id: numeracao.slot(None),
            token: None,
            chaves: Vec::new(),
            objetos: Vec::new(),
        });
    }
    slots
}

/// Os três objetos de uma chave. Uma chave que não é RSA, de certificado
/// ilegível ou sem mecanismo que a face exponha, fica de fora sem derrubar as
/// outras.
fn acrescentar(slot: &mut Slot, item: &ChaveDoToken, numeracao: &mut Numeracao) {
    let mecanismos: Vec<CK_MECHANISM_TYPE> = MECANISMOS
        .iter()
        .filter(|(m, _)| item.chave.mecanismos.contains(m))
        .map(|(_, t)| *t)
        .collect();
    if mecanismos.is_empty() {
        return;
    }
    let Ok(campos) = ler_certificado(&item.chave.certificado) else {
        return;
    };
    let Some(publica) = campos.publica.clone() else {
        return;
    };
    let rotulo = campos
        .nome
        .clone()
        .unwrap_or_else(|| item.chave.rotulo.clone());
    // `to_be_bytes_trimmed_vartime` tira os zeros à esquerda, como o Cryptoki
    // manda.
    let modulo = publica.n().to_be_bytes_trimmed_vartime().to_vec();
    let expoente = publica.e().to_be_bytes_trimmed_vartime().to_vec();
    let token = &item.token;
    let id = &item.chave.id;
    let certificado = numeracao.objeto(token, id, CERTIFICADO);
    let privada = numeracao.objeto(token, id, PRIVADA);
    let handle_publica = numeracao.objeto(token, id, PUBLICA);
    // O certificado antes da chave: há hospedeiro que pega o primeiro
    // certificado de uma busca e o toma pelo do titular.
    slot.objetos.extend([
        Objeto::certificado(certificado, &item.chave.certificado, &campos, &rotulo),
        Objeto::chave_privada(privada, &campos, &rotulo, &modulo, &expoente),
        Objeto::chave_publica(handle_publica, &campos, &rotulo, &modulo, &expoente),
    ]);
    slot.chaves.push(Chave {
        id: id.clone(),
        mecanismos,
        publica,
        privada,
        handle_publica,
    });
}
