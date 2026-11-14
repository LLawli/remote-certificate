//! A face Linux da estação: o módulo PKCS#11 (Cryptoki 2.40) que o p11-kit
//! carrega no Firefox, no Chromium, no Papers, no PJeOffice e no Assinador
//! Serpro. Mostra cada token do servidor como um token local e assina pelo
//! agente (`ipc`), que fala com o servidor. Portado do módulo do
//! RemoteID-linux.
//!
//! Regras que valem para todo o módulo, porque ele roda dentro do processo de
//! outro:
//!
//! - **Nenhum `panic` atravessa a fronteira C.** Toda função exportada passa
//!   por [`entrada`], que o converte em `CKR_GENERAL_ERROR` e grava mensagem
//!   e local no [`registro`].
//! - **Nada no stdout nem no stderr.** Dentro do `p11-kit server`, o stdout é
//!   o canal do protocolo.
//! - **Nenhuma trava segura uma pergunta à pessoa.** O `C_Sign` e o `C_Login`
//!   soltam a trava do módulo antes de ir ao agente, para a janela do OTP não
//!   congelar as outras chamadas da mesma aplicação.
//! - **Nenhum segredo no registro.** O PIN do `C_Login` não entra; dos dados
//!   a assinar, só o tamanho e o começo do SHA-256.

// A fronteira C do PKCS#11 é feita de ponteiros crus do hospedeiro: o
// `unsafe` é a natureza deste crate, e cada função diz o que espera deles.
#![allow(unsafe_code)]
// Os nomes são os da especificação, que é C: `C_GetSlotList`, `pulCount`.
#![allow(non_snake_case)]

mod canal;
mod funcoes;
mod objetos;
pub mod registro;
mod slots;
mod stubs;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use cryptoki_sys::*;

use slots::{Numeracao, Slot};

/// O estado do módulo. `None` antes do `C_Initialize`.
///
/// Uma trava só, e grossa: o volume é irrisório (poucos certificados, meia
/// dúzia de sessões), e serializar tudo elimina a classe de bug mais cara de
/// depurar dentro do processo de outro. A exceção é a conversa com o agente
/// (`canal`), que tem a trava dela.
static MODULO: Mutex<Option<Modulo>> = Mutex::new(None);

struct Modulo {
    slots: Vec<Slot>,
    numeracao: Numeracao,
    /// Quando a listagem veio do agente pela última vez.
    listado: Option<Instant>,
    sessoes: HashMap<CK_SESSION_HANDLE, Sessao>,
    proximo_handle: CK_SESSION_HANDLE,
    /// A geração da conexão com o agente em que o `C_Login` deu certo. O
    /// login vale para a aplicação inteira, não para uma sessão, e acaba se a
    /// conexão com o agente cair.
    login: Option<u64>,
    /// O que o último `C_Login` errado disse, para os flags do token.
    pin: SituacaoDoPin,
}

#[derive(Default, Clone, Copy)]
enum SituacaoDoPin {
    #[default]
    Normal,
    Restam(u32),
    Bloqueado,
}

struct Sessao {
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    /// O que sobrou da busca corrente: o Cryptoki a entrega em pedaços.
    busca: Option<Vec<CK_OBJECT_HANDLE>>,
    assinatura: Option<Operacao>,
    cifra: Option<Operacao>,
}

/// Uma operação de assinatura ou cifra, do `Init` até o fim.
///
/// Quem assina em fluxo (`C_SignUpdate`, depois `C_SignFinal`) junta os dados
/// aqui. Não é exotismo: o BouncyCastle nunca chama `C_Sign`, e é assim que o
/// PJeOffice assina.
struct Operacao {
    mecanismo: CK_MECHANISM_TYPE,
    chave: CK_OBJECT_HANDLE,
    acumulado: Vec<u8>,
}

impl Modulo {
    fn novo() -> Modulo {
        Modulo {
            slots: Vec::new(),
            numeracao: Numeracao::default(),
            listado: None,
            sessoes: HashMap::new(),
            proximo_handle: 1,
            login: None,
            pin: SituacaoDoPin::Normal,
        }
    }

    fn logado(&self) -> bool {
        self.login == Some(canal::geracao())
    }

    fn slot(&self, id: CK_SLOT_ID) -> Option<&Slot> {
        self.slots.iter().find(|s| s.id == id)
    }

    fn slot_da_sessao(&self, sessao: CK_SESSION_HANDLE) -> Option<&Slot> {
        self.slot(self.sessoes.get(&sessao)?.slot)
    }

    /// Troca os slots pelos da listagem nova. A sessão de um slot que sumiu
    /// acaba, como ao tirar o cartão.
    fn aplicar(&mut self, listagem: &[ipc::ChaveDoToken]) {
        self.slots = slots::montar(listagem, &mut self.numeracao);
        let ids: Vec<CK_SLOT_ID> = self.slots.iter().map(|s| s.id).collect();
        self.sessoes.retain(|_, s| ids.contains(&s.slot));
        self.listado = Some(Instant::now());
    }

    fn nova_sessao(&mut self, slot: CK_SLOT_ID, flags: CK_FLAGS) -> CK_SESSION_HANDLE {
        let h = self.proximo_handle;
        self.proximo_handle += 1;
        self.sessoes.insert(
            h,
            Sessao {
                slot,
                flags,
                busca: None,
                assinatura: None,
                cifra: None,
            },
        );
        h
    }
}

/// Tranca o estado, recuperando de envenenamento: um `panic` numa chamada não
/// pode inutilizar o módulo num navegador aberto há três dias.
fn trava<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Envolve o corpo de uma função exportada: o nome e os argumentos vão para
/// o [`registro`], que também segura o `panic`.
macro_rules! entrada {
    ($nome:literal, $campos:tt, $corpo:block) => {
        $crate::registro::chamada($nome, ::serde_json::json!($campos), || $corpo)
    };
}
use entrada;

/// A tabela de funções, na versão 2.40: a que o NSS pede, e o denominador
/// comum que p11-kit, NSS e GnuTLS carregam sem negociar. Os campos nomeados
/// fazem do compilador, e não da ordem das linhas, a garantia de que cada
/// ponteiro cai no lugar certo.
static LISTA: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(funcoes::C_Initialize),
    C_Finalize: Some(funcoes::C_Finalize),
    C_GetInfo: Some(funcoes::C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(funcoes::C_GetSlotList),
    C_GetSlotInfo: Some(funcoes::C_GetSlotInfo),
    C_GetTokenInfo: Some(funcoes::C_GetTokenInfo),
    C_GetMechanismList: Some(funcoes::C_GetMechanismList),
    C_GetMechanismInfo: Some(funcoes::C_GetMechanismInfo),
    C_InitToken: Some(stubs::C_InitToken),
    C_InitPIN: Some(stubs::C_InitPIN),
    C_SetPIN: Some(stubs::C_SetPIN),
    C_OpenSession: Some(funcoes::C_OpenSession),
    C_CloseSession: Some(funcoes::C_CloseSession),
    C_CloseAllSessions: Some(funcoes::C_CloseAllSessions),
    C_GetSessionInfo: Some(funcoes::C_GetSessionInfo),
    C_GetOperationState: Some(stubs::C_GetOperationState),
    C_SetOperationState: Some(stubs::C_SetOperationState),
    C_Login: Some(funcoes::C_Login),
    C_Logout: Some(funcoes::C_Logout),
    C_CreateObject: Some(stubs::C_CreateObject),
    C_CopyObject: Some(stubs::C_CopyObject),
    C_DestroyObject: Some(stubs::C_DestroyObject),
    C_GetObjectSize: Some(stubs::C_GetObjectSize),
    C_GetAttributeValue: Some(funcoes::C_GetAttributeValue),
    C_SetAttributeValue: Some(stubs::C_SetAttributeValue),
    C_FindObjectsInit: Some(funcoes::C_FindObjectsInit),
    C_FindObjects: Some(funcoes::C_FindObjects),
    C_FindObjectsFinal: Some(funcoes::C_FindObjectsFinal),
    C_EncryptInit: Some(funcoes::C_EncryptInit),
    C_Encrypt: Some(funcoes::C_Encrypt),
    C_EncryptUpdate: Some(stubs::C_EncryptUpdate),
    C_EncryptFinal: Some(stubs::C_EncryptFinal),
    C_DecryptInit: Some(stubs::C_DecryptInit),
    C_Decrypt: Some(stubs::C_Decrypt),
    C_DecryptUpdate: Some(stubs::C_DecryptUpdate),
    C_DecryptFinal: Some(stubs::C_DecryptFinal),
    C_DigestInit: Some(stubs::C_DigestInit),
    C_Digest: Some(stubs::C_Digest),
    C_DigestUpdate: Some(stubs::C_DigestUpdate),
    C_DigestKey: Some(stubs::C_DigestKey),
    C_DigestFinal: Some(stubs::C_DigestFinal),
    C_SignInit: Some(funcoes::C_SignInit),
    C_Sign: Some(funcoes::C_Sign),
    C_SignUpdate: Some(funcoes::C_SignUpdate),
    C_SignFinal: Some(funcoes::C_SignFinal),
    C_SignRecoverInit: Some(stubs::C_SignRecoverInit),
    C_SignRecover: Some(stubs::C_SignRecover),
    C_VerifyInit: Some(stubs::C_VerifyInit),
    C_Verify: Some(stubs::C_Verify),
    C_VerifyUpdate: Some(stubs::C_VerifyUpdate),
    C_VerifyFinal: Some(stubs::C_VerifyFinal),
    C_VerifyRecoverInit: Some(stubs::C_VerifyRecoverInit),
    C_VerifyRecover: Some(stubs::C_VerifyRecover),
    C_DigestEncryptUpdate: Some(stubs::C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(stubs::C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(stubs::C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(stubs::C_DecryptVerifyUpdate),
    C_GenerateKey: Some(stubs::C_GenerateKey),
    C_GenerateKeyPair: Some(stubs::C_GenerateKeyPair),
    C_WrapKey: Some(stubs::C_WrapKey),
    C_UnwrapKey: Some(stubs::C_UnwrapKey),
    C_DeriveKey: Some(stubs::C_DeriveKey),
    C_SeedRandom: Some(stubs::C_SeedRandom),
    C_GenerateRandom: Some(stubs::C_GenerateRandom),
    C_GetFunctionStatus: Some(stubs::C_GetFunctionStatus),
    C_CancelFunction: Some(stubs::C_CancelFunction),
    C_WaitForSlotEvent: Some(stubs::C_WaitForSlotEvent),
};

/// O único símbolo que o hospedeiro procura pelo nome; o resto sai da
/// tabela. Funciona antes do `C_Initialize`, que é a ordem do p11-kit.
///
/// # Safety
///
/// `ppFunctionList` é nulo ou aponta para um ponteiro gravável.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    entrada!("C_GetFunctionList", {}, {
        if ppFunctionList.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // O hospedeiro só lê a tabela; o ponteiro é mutável pela convenção do
        // cabeçalho C.
        unsafe { *ppFunctionList = &raw const LISTA as *mut CK_FUNCTION_LIST };
        CKR_OK
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_tabela_nao_tem_ponteiro_nulo() {
        // O p11-kit e o NSS chamam sem conferir: um campo nulo é segfault
        // dentro do navegador, não um erro.
        let ponteiros = (size_of::<CK_FUNCTION_LIST>() - size_of::<usize>()) / size_of::<usize>();
        let tabela = unsafe {
            std::slice::from_raw_parts((&raw const LISTA as *const usize).add(1), ponteiros)
        };
        assert_eq!(tabela.len(), 68, "a lista 2.40 tem 68 funções");
        assert!(tabela.iter().all(|p| *p != 0));
    }
}
