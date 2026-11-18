//! Os slots: um por token do servidor, montados da listagem do agente.
//!
//! Os números de slot e de objeto ficam estáveis enquanto o módulo vive: o
//! mesmo token e a mesma chave voltam sempre com o mesmo número, mesmo que a
//! listagem mude a ordem ou um token suma e volte.

use std::collections::BTreeMap;

use cryptoki_sys::*;
use ipc::ChaveDoToken;
use protocolo::Mecanismo;

use crate::objetos::{Atributo, Objeto, Publica, ler_certificado};

/// Os mecanismos que a face expõe, e o nome de cada um no contrato.
pub const MECANISMOS: [(Mecanismo, CK_MECHANISM_TYPE); 6] = [
    (Mecanismo::RsaPkcs, CKM_RSA_PKCS),
    (Mecanismo::Sha256RsaPkcs, CKM_SHA256_RSA_PKCS),
    (Mecanismo::Sha384RsaPkcs, CKM_SHA384_RSA_PKCS),
    (Mecanismo::Sha512RsaPkcs, CKM_SHA512_RSA_PKCS),
    (Mecanismo::RsaPkcsPss, CKM_RSA_PKCS_PSS),
    (Mecanismo::Ecdsa, CKM_ECDSA),
];

pub fn do_contrato(tipo: CK_MECHANISM_TYPE) -> Option<Mecanismo> {
    MECANISMOS.iter().find(|(_, t)| *t == tipo).map(|(m, _)| *m)
}

/// Se o mecanismo é do tipo da chave: um driver que declarasse ECDSA numa
/// chave RSA faria o hospedeiro pedir uma assinatura que nunca confere.
fn serve(tipo: CK_MECHANISM_TYPE, publica: &Publica) -> bool {
    match publica {
        Publica::Rsa(_) => tipo != CKM_ECDSA,
        Publica::Ec { .. } => tipo == CKM_ECDSA,
    }
}

/// Uma chave que assina: o par de objetos que aponta para ela.
pub struct Chave {
    /// O id da chave no token do servidor.
    pub id: String,
    pub mecanismos: Vec<CK_MECHANISM_TYPE>,
    pub publica: Publica,
    pub privada: CK_OBJECT_HANDLE,
    pub handle_publica: CK_OBJECT_HANDLE,
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

    /// O menor e o maior tamanho, em bits, das chaves que declaram o
    /// mecanismo, para `C_GetMechanismInfo`. `None` se nenhuma o declara.
    pub fn bits(&self, tipo: CK_MECHANISM_TYPE) -> Option<(CK_ULONG, CK_ULONG)> {
        let bits = self
            .chaves
            .iter()
            .filter(|c| c.mecanismos.contains(&tipo))
            .map(|c| c.publica.bits());
        Some((bits.clone().min()?, bits.max()?))
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

/// Os três objetos de uma chave. Uma chave que não é RSA nem EC de curva
/// conhecida, de certificado ilegível ou sem mecanismo que a face exponha,
/// fica de fora sem derrubar as outras.
fn acrescentar(slot: &mut Slot, item: &ChaveDoToken, numeracao: &mut Numeracao) {
    let Ok(campos) = ler_certificado(&item.chave.certificado) else {
        return;
    };
    let Some(publica) = campos.publica.clone() else {
        return;
    };
    let mecanismos: Vec<CK_MECHANISM_TYPE> = MECANISMOS
        .iter()
        .filter(|(m, t)| item.chave.mecanismos.contains(m) && serve(*t, &publica))
        .map(|(_, t)| *t)
        .collect();
    if mecanismos.is_empty() {
        return;
    }
    let rotulo = campos
        .nome
        .clone()
        .unwrap_or_else(|| item.chave.rotulo.clone());
    let token = &item.token;
    let id = &item.chave.id;
    let certificado = numeracao.objeto(token, id, CERTIFICADO);
    let privada = numeracao.objeto(token, id, PRIVADA);
    let handle_publica = numeracao.objeto(token, id, PUBLICA);
    // O certificado antes da chave: há hospedeiro que pega o primeiro
    // certificado de uma busca e o toma pelo do titular.
    slot.objetos.extend([
        Objeto::certificado(certificado, &item.chave.certificado, &campos, &rotulo),
        Objeto::chave_privada(privada, &campos, &rotulo, &publica),
        Objeto::chave_publica(handle_publica, &campos, &rotulo, &publica),
    ]);
    slot.chaves.push(Chave {
        id: id.clone(),
        mecanismos,
        publica,
        privada,
        handle_publica,
    });
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::objetos::ulong;
    use protocolo::Chave as ChaveDoContrato;

    /// Uma chave P-384 com um certificado dela.
    fn listagem_ec(mecanismos: Vec<Mecanismo>) -> Vec<ChaveDoToken> {
        let par = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let certificado = rcgen::CertificateParams::new(["ec.local".to_string()])
            .unwrap()
            .self_signed(&par)
            .unwrap();
        vec![ChaveDoToken {
            token: "GD".into(),
            chave: ChaveDoContrato {
                id: "0ec0".into(),
                rotulo: "EC".into(),
                certificado: certificado.der().to_vec(),
                mecanismos,
            },
        }]
    }

    #[test]
    fn a_chave_ec_mostra_a_curva_o_ponto_e_so_o_ecdsa() {
        // Um driver que declarasse RSA numa chave EC: fica só o que serve.
        let listagem = listagem_ec(vec![Mecanismo::RsaPkcs, Mecanismo::Ecdsa]);
        let slots = montar(&listagem, &mut Numeracao::default());
        let [slot] = &slots[..] else {
            panic!("um slot");
        };
        let [chave] = &slot.chaves[..] else {
            panic!("uma chave");
        };
        assert_eq!(chave.mecanismos, [CKM_ECDSA]);
        assert_eq!(slot.mecanismos(), [CKM_ECDSA]);
        assert_eq!(slot.bits(CKM_ECDSA), Some((384, 384)));
        assert_eq!(slot.bits(CKM_RSA_PKCS), None);
        assert_eq!(chave.publica.bytes_da_assinatura(), 96, "r‖s da P-384");

        let p384 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        for handle in [chave.privada, chave.handle_publica] {
            let objeto = slot.objeto(handle).unwrap();
            assert_eq!(objeto.atributo(CKA_KEY_TYPE), Some(&ulong(CKK_EC)[..]));
            assert_eq!(objeto.atributo(CKA_EC_PARAMS), Some(&p384[..]));
            assert_eq!(objeto.atributo(CKA_MODULUS), None);
        }
        let publica = slot.objeto(chave.handle_publica).unwrap();
        let ponto = publica.atributo(CKA_EC_POINT).unwrap();
        // Um OCTET STRING com o ponto não comprimido: 0x04, x e y.
        assert_eq!(ponto[..3], [0x04, 97, 0x04]);
        assert_eq!(ponto.len(), 2 + 97);
        assert_eq!(publica.atributo(CKA_ENCRYPT), Some(&[CK_FALSE][..]));
        assert!(slot.objeto(chave.privada).unwrap().e_sensivel(CKA_VALUE));
    }

    #[test]
    fn chave_ec_sem_ecdsa_declarado_fica_de_fora() {
        let listagem = listagem_ec(vec![Mecanismo::Sha256RsaPkcs]);
        let slots = montar(&listagem, &mut Numeracao::default());
        assert!(slots[0].chaves.is_empty());
        assert!(slots[0].objetos.is_empty());
    }
}
