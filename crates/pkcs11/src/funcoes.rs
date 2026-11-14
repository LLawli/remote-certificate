//! As funções Cryptoki que a face faz de fato (portadas do RemoteID-linux).
//!
//! Todas recebem ponteiros crus do hospedeiro e passam por [`entrada`]. O
//! corpo inteiro de cada uma é a conversa com esses ponteiros, por isso o
//! `unsafe` vale para a função toda e não bloco a bloco.

#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::time::{Duration, Instant};

use cryptoki_sys::*;
use ipc::{DaFace, DoAgente, TipoDeFalha};
use protocolo::Segredo;
use rsa::Pkcs1v15Encrypt;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::objetos::Objeto;
use crate::slots::{self, Slot};
use crate::{Login, MODULO, Modulo, Operacao, SituacaoDoPin, canal, entrada, registro, trava};

/// O que a especificação põe em `ulValueLen` quando o atributo não existe, e
/// nos campos de `CK_TOKEN_INFO` que o token não sabe.
const INDISPONIVEL: CK_ULONG = CK_UNAVAILABLE_INFORMATION;

const VERSAO: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
const FABRICANTE: &str = "remote-certificate";

/// Quanto a listagem do agente vale antes de ser pedida de novo. Cada uma vai
/// ao servidor e aos drivers, e o NSS confere os slots o tempo todo.
const VALIDADE_DA_LISTAGEM: Duration = Duration::from_secs(10);

/// O PIN pessoal, em bytes. O servidor aceita de 4 a 64 caracteres; o máximo
/// aqui é folgado porque um caractere acentuado ocupa mais de um byte.
const PIN_MINIMO: CK_ULONG = 4;
const PIN_MAXIMO: CK_ULONG = 255;

/// O maior bloco que vai ao agente. O WebSocket do servidor leva até 4 MiB
/// por mensagem, com os dados em base64 (um terço a mais) e o envelope JSON.
const LIMITE_DOS_DADOS: usize = 3 * 1024 * 1024 - 64 * 1024;

/// Copia `texto` num campo de tamanho fixo. Os campos de texto do Cryptoki
/// são completados com espaço e não terminam em NUL: o `p11tool` e o
/// `certutil` imprimem o campo inteiro.
fn preencher(destino: &mut [u8], texto: &str) {
    destino.fill(b' ');
    let mut n = texto.len().min(destino.len());
    // Sem cortar um caractere ao meio.
    while !texto.is_char_boundary(n) {
        n -= 1;
    }
    destino[..n].copy_from_slice(&texto.as_bytes()[..n]);
}

/// Responde uma lista em duas passadas, como a especificação manda: com a
/// lista nula, só o tamanho.
unsafe fn entregar_lista<T: Copy>(itens: &[T], lista: *mut T, contagem: *mut CK_ULONG) -> CK_RV {
    if contagem.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let pedido = *contagem as usize;
    *contagem = itens.len() as CK_ULONG;
    if lista.is_null() {
        return CKR_OK;
    }
    if pedido < itens.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(itens.as_ptr(), lista, itens.len());
    CKR_OK
}

/// O módulo inicializado, ou o erro que a especificação manda.
macro_rules! modulo {
    ($guarda:ident) => {
        match $guarda.as_mut() {
            Some(m) => m,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        }
    };
}

/// Pede a listagem ao agente se a última venceu, sem a trava do módulo e sem
/// esperar a conexão: ocupada (uma assinatura esperando o OTP), fica a que
/// já havia.
fn atualizar() {
    {
        let guarda = trava(&MODULO);
        let Some(modulo) = guarda.as_ref() else {
            return;
        };
        if modulo
            .listado
            .is_some_and(|quando| quando.elapsed() < VALIDADE_DA_LISTAGEM)
        {
            return;
        }
    }
    let Some(resposta) = canal::pedir_se_livre(&DaFace::Listar {}) else {
        return;
    };
    let mut guarda = trava(&MODULO);
    let Some(modulo) = guarda.as_mut() else {
        return;
    };
    match resposta {
        Ok((DoAgente::Chaves { chaves }, _)) => modulo.aplicar(&chaves),
        // Sem agente, ou ele falhou: o slot vazio, e outra tentativa depois.
        outra => {
            if let Err(e) = &outra {
                registro::evento("agente", json!({ "erro": e.kind().to_string() }));
            }
            modulo.aplicar(&[]);
        }
    }
}

// Ciclo de vida

pub(crate) unsafe extern "C" fn C_Initialize(pInitArgs: *mut c_void) -> CK_RV {
    entrada!("C_Initialize", {}, {
        if !pInitArgs.is_null() {
            let args = &*(pInitArgs as *const CK_C_INITIALIZE_ARGS);
            if !args.pReserved.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            // Os callbacks de mutex do hospedeiro ficam sem uso: o módulo se
            // tranca sozinho, e é seguro com qualquer combinação deles.
        }
        let mut guarda = trava(&MODULO);
        if guarda.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        // Nada de agente aqui: o p11-kit carrega todos os módulos em todo
        // programa que o usa, e só quem lista slots precisa da listagem.
        *guarda = Some(Modulo::novo());
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_Finalize(pReserved: *mut c_void) -> CK_RV {
    entrada!("C_Finalize", {}, {
        if !pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if trava(&MODULO).take().is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        // Fechar a conexão com o agente acaba o login desta aplicação.
        canal::fechar();
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    entrada!("C_GetInfo", {}, {
        if trava(&MODULO).is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *pInfo;
        info.cryptokiVersion = CK_VERSION {
            major: 2,
            minor: 40,
        };
        info.flags = 0;
        info.libraryVersion = VERSAO;
        preencher(&mut info.manufacturerID, FABRICANTE);
        preencher(&mut info.libraryDescription, "Tokens do servidor");
        CKR_OK
    })
}

// Slot e token

pub(crate) unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_GetSlotList", {"so_contagem": pSlotList.is_null()}, {
        atualizar();
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        // Todo slot tem token, mesmo o vazio: ver `slots::montar`.
        let ids: Vec<CK_SLOT_ID> = modulo.slots.iter().map(|s| s.id).collect();
        entregar_lista(&ids, pSlotList, pulCount)
    })
}

/// O slot `id`, depois de conferir a listagem.
fn com_o_slot<R>(id: CK_SLOT_ID, f: impl FnOnce(&Modulo, &Slot) -> R) -> Result<R, CK_RV> {
    atualizar();
    let guarda = trava(&MODULO);
    let modulo = guarda.as_ref().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    let slot = modulo.slot(id).ok_or(CKR_SLOT_ID_INVALID)?;
    Ok(f(modulo, slot))
}

pub(crate) unsafe extern "C" fn C_GetSlotInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut CK_SLOT_INFO,
) -> CK_RV {
    entrada!("C_GetSlotInfo", {"slot": slotID}, {
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let resultado = com_o_slot(slotID, |_, slot| {
            let info = &mut *pInfo;
            let descricao = match &slot.token {
                Some(token) => format!("{FABRICANTE}: {token}"),
                None => format!("{FABRICANTE} (sem token)"),
            };
            preencher(&mut info.slotDescription, &descricao);
            preencher(&mut info.manufacturerID, FABRICANTE);
            // Com CKF_REMOVABLE_DEVICE: é o que faz o NSS voltar a conferir o
            // slot quando os tokens do servidor mudam.
            info.flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE;
            info.hardwareVersion = VERSAO;
            info.firmwareVersion = VERSAO;
        });
        resultado.err().unwrap_or(CKR_OK)
    })
}

/// Os flags do token. O de verdade pede login: o PIN pessoal entra pelo
/// `C_Login`, e os assinadores o pedem como pedem o de um token físico. O
/// vazio não tem o que proteger.
fn flags_do_token(slot: &Slot, pin: SituacaoDoPin) -> CK_FLAGS {
    let mut flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED;
    if slot.token.is_none() {
        return flags;
    }
    flags |= CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    flags |= match pin {
        SituacaoDoPin::Normal => 0,
        SituacaoDoPin::Restam(1) => CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY,
        SituacaoDoPin::Restam(_) => CKF_USER_PIN_COUNT_LOW,
        SituacaoDoPin::Bloqueado => CKF_USER_PIN_LOCKED,
    };
    flags
}

pub(crate) unsafe extern "C" fn C_GetTokenInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut CK_TOKEN_INFO,
) -> CK_RV {
    entrada!("C_GetTokenInfo", {"slot": slotID}, {
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let resultado = com_o_slot(slotID, |modulo, slot| {
            let info = &mut *pInfo;
            let rotulo = slot.token.as_deref().unwrap_or(FABRICANTE);
            preencher(&mut info.label, rotulo);
            preencher(&mut info.manufacturerID, FABRICANTE);
            preencher(&mut info.model, "token remoto");
            // Estável para o mesmo token, que é o que o NSS usa para
            // reconhecê-lo depois.
            let serie: String = Sha256::digest(rotulo.as_bytes())[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            preencher(&mut info.serialNumber, &serie);
            info.flags = flags_do_token(slot, modulo.pin);
            info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
            info.ulSessionCount = modulo
                .sessoes
                .values()
                .filter(|s| s.slot == slot.id)
                .count() as CK_ULONG;
            info.ulMaxRwSessionCount = 0;
            info.ulRwSessionCount = 0;
            // Não pode ser 0: o NSS confere o tamanho da senha contra o
            // máximo antes do C_Login, e com 0 recusa toda senha sem tentar.
            info.ulMinPinLen = PIN_MINIMO;
            info.ulMaxPinLen = PIN_MAXIMO;
            info.ulTotalPublicMemory = INDISPONIVEL;
            info.ulFreePublicMemory = INDISPONIVEL;
            info.ulTotalPrivateMemory = INDISPONIVEL;
            info.ulFreePrivateMemory = INDISPONIVEL;
            info.hardwareVersion = VERSAO;
            info.firmwareVersion = VERSAO;
            preencher(&mut info.utcTime, "");
        });
        resultado.err().unwrap_or(CKR_OK)
    })
}

pub(crate) unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_GetMechanismList", {"slot": slotID, "so_contagem": pMechanismList.is_null()}, {
        match com_o_slot(slotID, |_, slot| slot.mecanismos()) {
            Ok(mecanismos) => entregar_lista(&mecanismos, pMechanismList, pulCount),
            Err(rv) => rv,
        }
    })
}

pub(crate) unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    entrada!("C_GetMechanismInfo", {"slot": slotID, "mecanismo": registro::mecanismo(type_)}, {
        let (mecanismos, (minimo, maximo)) = match com_o_slot(slotID, |_, s| (s.mecanismos(), s.bits())) {
            Ok(r) => r,
            Err(rv) => return rv,
        };
        // Só o que alguma chave do slot declara: o cliente nunca expõe um
        // mecanismo que o driver não declarou.
        if !mecanismos.contains(&type_) {
            return CKR_MECHANISM_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // O CKM_RSA_PKCS anuncia cifra além de assinatura. Desde o JDK
        // 11.0.6 (JDK-8176837) o SunPKCS11 só registra o
        // `Cipher.RSA/ECB/PKCS1Padding` de um token que anuncia CKF_ENCRYPT,
        // e esse Cipher é a única porta da JCA para RSA cru: sem ele o
        // signer4j do PJeOffice cai num provedor de software e não autentica.
        // Com a chave privada ele vira C_SignInit e C_Sign; o C_Encrypt de
        // verdade só cifra com a pública.
        let flags = if type_ == CKM_RSA_PKCS {
            CKF_SIGN | CKF_ENCRYPT
        } else {
            CKF_SIGN
        };
        *pInfo = CK_MECHANISM_INFO {
            ulMinKeySize: minimo,
            ulMaxKeySize: maximo,
            flags,
        };
        CKR_OK
    })
}

// Sessões

pub(crate) unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: *mut c_void,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    entrada!("C_OpenSession", {"slot": slotID, "flags": flags}, {
        if phSession.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        // O token é só de leitura: uma sessão R/W seria promessa vazia.
        if flags & CKF_RW_SESSION != 0 {
            return CKR_TOKEN_WRITE_PROTECTED;
        }
        if let Err(rv) = com_o_slot(slotID, |_, _| ()) {
            return rv;
        }
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if modulo.slot(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        *phSession = modulo.nova_sessao(slotID, flags);
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!("C_CloseSession", {"sessao": hSession}, {
        let mut guarda = trava(&MODULO);
        match modulo!(guarda).sessoes.remove(&hSession) {
            Some(_) => CKR_OK,
            None => CKR_SESSION_HANDLE_INVALID,
        }
    })
}

pub(crate) unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    entrada!("C_CloseAllSessions", {"slot": slotID}, {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if modulo.slot(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        modulo.sessoes.retain(|_, s| s.slot != slotID);
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut CK_SESSION_INFO,
) -> CK_RV {
    entrada!("C_GetSessionInfo", {"sessao": hSession}, {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let logado = modulo.logado();
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        *pInfo = CK_SESSION_INFO {
            slotID: sessao.slot,
            // Tem de refletir o login: o NSS confere aqui, depois do C_Login,
            // e com a sessão ainda pública pede a senha de novo, em laço.
            state: if logado {
                CKS_RO_USER_FUNCTIONS
            } else {
                CKS_RO_PUBLIC_SESSION
            },
            flags: sessao.flags,
            ulDeviceError: 0,
        };
        CKR_OK
    })
}

// Objetos

unsafe fn ler_gabarito(
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, CK_RV> {
    if ulCount == 0 {
        return Ok(Vec::new());
    }
    if pTemplate.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    std::slice::from_raw_parts(pTemplate, ulCount as usize)
        .iter()
        .map(|a| {
            if a.ulValueLen == INDISPONIVEL {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            Ok((
                a.type_,
                bloco_do_host(a.pValue as *mut CK_BYTE, a.ulValueLen)?.to_vec(),
            ))
        })
        .collect()
}

pub(crate) unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!("C_FindObjectsInit", {"sessao": hSession, "atributos": registro::atributos(pTemplate, ulCount)}, {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let gabarito = match ler_gabarito(pTemplate, ulCount) {
            Ok(g) => g,
            Err(rv) => return rv,
        };
        let achados = modulo
            .slot_da_sessao(hSession)
            .map(|s| s.buscar(&gabarito))
            .unwrap_or_default();
        let Some(sessao) = modulo.sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if sessao.busca.is_some() {
            return CKR_OPERATION_ACTIVE;
        }
        sessao.busca = Some(achados);
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_FindObjects", {"sessao": hSession, "maximo": ulMaxObjectCount}, {
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(fila) = sessao.busca.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if pulObjectCount.is_null() || (phObject.is_null() && ulMaxObjectCount != 0) {
            return CKR_ARGUMENTS_BAD;
        }
        let n = fila.len().min(ulMaxObjectCount as usize);
        for (i, h) in fila.drain(..n).enumerate() {
            *phObject.add(i) = h;
        }
        *pulObjectCount = n as CK_ULONG;
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!("C_FindObjectsFinal", {"sessao": hSession}, {
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        match sessao.busca.take() {
            Some(_) => CKR_OK,
            None => CKR_OPERATION_NOT_INITIALIZED,
        }
    })
}

/// Duas passadas, como manda a especificação, e o erro é por atributo: os que
/// existem são copiados mesmo quando outro falta, e o que faltou fica com
/// `CK_UNAVAILABLE_INFORMATION`. Abortar na primeira falta deixaria o
/// hospedeiro sem nada por perguntar um atributo a mais.
pub(crate) unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    entrada!("C_GetAttributeValue", {"sessao": hSession, "objeto": hObject, "atributos": registro::atributos(pTemplate, ulCount)}, {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        if !modulo.sessoes.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let Some(objeto) = modulo.slot_da_sessao(hSession).and_then(|s| s.objeto(hObject)) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        if pTemplate.is_null() && ulCount != 0 {
            return CKR_ARGUMENTS_BAD;
        }
        copiar_atributos(objeto, pTemplate, ulCount)
    })
}

unsafe fn copiar_atributos(
    objeto: &Objeto,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    let mut rv = CKR_OK;
    for i in 0..ulCount as usize {
        let attr = &mut *pTemplate.add(i);
        // Antes de procurar: `CKA_VALUE` existe no certificado, mas na chave
        // privada é sensível.
        if objeto.e_sensivel(attr.type_) {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        let Some(valor) = objeto.atributo(attr.type_) else {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        };
        if attr.pValue.is_null() {
            attr.ulValueLen = valor.len() as CK_ULONG;
            continue;
        }
        if (attr.ulValueLen as usize) < valor.len() {
            attr.ulValueLen = INDISPONIVEL;
            rv = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        std::ptr::copy_nonoverlapping(valor.as_ptr(), attr.pValue as *mut u8, valor.len());
        attr.ulValueLen = valor.len() as CK_ULONG;
    }
    rv
}

// Login

/// O PIN pessoal: o agente o leva ao servidor, que confere e abre o login
/// desta aplicação. Errar conta para o bloqueio do dispositivo.
pub(crate) unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: *mut CK_UTF8CHAR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    // O PIN não vai ao registro, nem o tamanho dele.
    entrada!("C_Login", {"sessao": hSession, "usuario": userType}, {
        {
            let mut guarda = trava(&MODULO);
            let modulo = modulo!(guarda);
            if !modulo.sessoes.contains_key(&hSession) {
                return CKR_SESSION_HANDLE_INVALID;
            }
            match userType {
                CKU_USER => {}
                // Nenhuma chave pede reautenticação por operação.
                CKU_CONTEXT_SPECIFIC => return CKR_OPERATION_NOT_INITIALIZED,
                _ => return CKR_USER_TYPE_INVALID,
            }
            if modulo.logado() {
                return CKR_USER_ALREADY_LOGGED_IN;
            }
        }
        // Sem PIN é o caminho de autenticação protegido, que este token não
        // tem: o PIN pessoal vem sempre do hospedeiro.
        if pPin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !(PIN_MINIMO..=PIN_MAXIMO).contains(&ulPinLen) {
            return CKR_PIN_LEN_RANGE;
        }
        let bytes = std::slice::from_raw_parts(pPin, ulPinLen as usize);
        let Ok(pin) = String::from_utf8(bytes.to_vec()) else {
            return CKR_PIN_INCORRECT;
        };
        let resposta = canal::pedir(&DaFace::Entrar {
            pin: Segredo::novo(pin),
        });
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        match resposta {
            Ok((DoAgente::Entrou { sessao }, geracao)) => {
                modulo.login = Some(Login {
                    geracao,
                    prazo: sessao.map(Duration::from_secs),
                    uso: Instant::now(),
                });
                modulo.pin = SituacaoDoPin::Normal;
                CKR_OK
            }
            Ok((DoAgente::Falha { erro }, _)) => {
                registro::evento("falha", json!({ "etapa": "entrar", "erro": erro.tipo }));
                match erro.tipo {
                    TipoDeFalha::PinErrado => {
                        modulo.pin = erro.restantes.map_or(SituacaoDoPin::Normal, SituacaoDoPin::Restam);
                        CKR_PIN_INCORRECT
                    }
                    TipoDeFalha::Bloqueado => {
                        modulo.pin = SituacaoDoPin::Bloqueado;
                        CKR_PIN_LOCKED
                    }
                    _ => rv_da_falha(erro.tipo),
                }
            }
            Ok(_) => CKR_FUNCTION_FAILED,
            Err(e) => {
                registro::evento("falha", json!({ "etapa": "entrar", "erro": e.kind().to_string() }));
                CKR_DEVICE_ERROR
            }
        }
    })
}

pub(crate) unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    entrada!("C_Logout", {"sessao": hSession}, {
        {
            let mut guarda = trava(&MODULO);
            let modulo = modulo!(guarda);
            if !modulo.sessoes.contains_key(&hSession) {
                return CKR_SESSION_HANDLE_INVALID;
            }
            if !modulo.logado() {
                return CKR_USER_NOT_LOGGED_IN;
            }
            modulo.login = None;
        }
        // O login aqui já acabou; o do servidor acaba junto, ou vence sozinho
        // se o agente não responder.
        let _ = canal::pedir(&DaFace::Sair {});
        CKR_OK
    })
}

// Assinatura e cifra

/// O que o hospedeiro entende de uma falha do agente. A mensagem fica no
/// registro.
fn rv_da_falha(tipo: TipoDeFalha) -> CK_RV {
    match tipo {
        TipoDeFalha::PinErrado => CKR_PIN_INCORRECT,
        TipoDeFalha::Bloqueado => CKR_PIN_LOCKED,
        TipoDeFalha::NaoAutenticado => CKR_USER_NOT_LOGGED_IN,
        TipoDeFalha::Cancelado => CKR_FUNCTION_CANCELED,
        TipoDeFalha::MecanismoNaoSuportado => CKR_MECHANISM_INVALID,
        TipoDeFalha::ChaveAusente => CKR_KEY_HANDLE_INVALID,
        TipoDeFalha::TokenDesconhecido
        | TipoDeFalha::TokenParado
        | TipoDeFalha::Token
        | TipoDeFalha::SemServidor
        | TipoDeFalha::NaoPareado => CKR_DEVICE_ERROR,
        TipoDeFalha::PedidoInvalido | TipoDeFalha::Interno | TipoDeFalha::Outro => {
            CKR_FUNCTION_FAILED
        }
    }
}

/// O mecanismo pedido, e se veio com parâmetro. Nenhum dos que a face expõe
/// tem; um parâmetro é sinal de que o hospedeiro queria PSS ou OAEP.
unsafe fn ler_mecanismo(pMechanism: *mut CK_MECHANISM) -> Result<(CK_MECHANISM_TYPE, bool), CK_RV> {
    if pMechanism.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mecanismo = &*pMechanism;
    let com_parametro = mecanismo.ulParameterLen != 0 || !mecanismo.pParameter.is_null();
    Ok((mecanismo.mechanism, com_parametro))
}

#[derive(Clone, Copy, PartialEq)]
enum Uso {
    Assinar,
    Cifrar,
}

/// O começo comum de `C_SignInit` e `C_EncryptInit`: a chave tem de existir,
/// ser da classe que a operação usa e declarar o mecanismo.
unsafe fn iniciar(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
    uso: Uso,
) -> CK_RV {
    let mut guarda = trava(&MODULO);
    let modulo = modulo!(guarda);
    let logado = modulo.logado();
    let Some(slot) = modulo.slot_da_sessao(hSession) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let (mecanismo, com_parametro) = match ler_mecanismo(pMechanism) {
        Ok(m) => m,
        Err(rv) => return rv,
    };
    let chave = match uso {
        Uso::Assinar => slot.da_privada(hKey),
        Uso::Cifrar => slot.da_publica(hKey),
    };
    let Some(chave) = chave else {
        // É uma chave, mas não serve para esta operação.
        return match slot.objeto(hKey).and_then(Objeto::classe) {
            Some(CKO_PRIVATE_KEY | CKO_PUBLIC_KEY) => CKR_KEY_FUNCTION_NOT_PERMITTED,
            _ => CKR_KEY_HANDLE_INVALID,
        };
    };
    let permitido = match uso {
        Uso::Assinar => chave.mecanismos.contains(&mecanismo),
        Uso::Cifrar => mecanismo == CKM_RSA_PKCS && chave.mecanismos.contains(&CKM_RSA_PKCS),
    };
    // Primeiro se o mecanismo existe: um RSA-PSS pedido com os parâmetros
    // dele é "não suportado" (o token não serve para TLS 1.3), não
    // "parâmetro errado".
    if !permitido {
        return CKR_MECHANISM_INVALID;
    }
    if com_parametro {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    // Cifrar com a pública não precisa do login; assinar precisa.
    if uso == Uso::Assinar && !logado {
        return CKR_USER_NOT_LOGGED_IN;
    }
    let sessao = modulo.sessoes.get_mut(&hSession).expect("conferida acima");
    let ativa = match uso {
        Uso::Assinar => &mut sessao.assinatura,
        Uso::Cifrar => &mut sessao.cifra,
    };
    if ativa.is_some() {
        return CKR_OPERATION_ACTIVE;
    }
    *ativa = Some(Operacao {
        mecanismo,
        chave: hKey,
        acumulado: Vec::new(),
    });
    CKR_OK
}

pub(crate) unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!("C_SignInit", {"sessao": hSession, "mecanismo": registro::mecanismo_de(pMechanism), "chave": hKey}, {
        iniciar(hSession, pMechanism, hKey, Uso::Assinar)
    })
}

/// Um bloco do hospedeiro. Comprimento zero é legítimo, e aí o ponteiro pode
/// ser nulo.
unsafe fn bloco_do_host<'a>(p: *mut CK_BYTE, n: CK_ULONG) -> Result<&'a [u8], CK_RV> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(std::slice::from_raw_parts(p, n as usize))
}

/// A parte das duas passadas que `C_Sign`, `C_SignFinal` e `C_Encrypt` têm
/// igual: com o buffer nulo só o tamanho, com o buffer pequeno o erro, e nos
/// dois casos a operação continua ativa, para o hospedeiro voltar com espaço.
/// `Err` é a resposta pronta.
unsafe fn conferir_saida(
    bytes: usize,
    pSaida: *mut CK_BYTE,
    pulSaidaLen: *mut CK_ULONG,
) -> Result<(), CK_RV> {
    if pulSaidaLen.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let cabe = *pulSaidaLen as usize >= bytes;
    *pulSaidaLen = bytes as CK_ULONG;
    if pSaida.is_null() {
        return Err(CKR_OK);
    }
    if !cabe {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    Ok(())
}

unsafe fn entregar(
    bloco: &[u8],
    bytes: usize,
    pSaida: *mut CK_BYTE,
    pulSaidaLen: *mut CK_ULONG,
) -> CK_RV {
    // Toda assinatura e cifra RSA tem o tamanho do módulo; outra coisa é
    // defeito, e o hospedeiro a recusaria adiante.
    if bloco.len() != bytes {
        return CKR_FUNCTION_FAILED;
    }
    std::ptr::copy_nonoverlapping(bloco.as_ptr(), pSaida, bytes);
    *pulSaidaLen = bytes as CK_ULONG;
    CKR_OK
}

/// O que cabe num `CKM_RSA_PKCS`: um bloco (em geral um DigestInfo) que deixa
/// espaço para o padding do PKCS#1 v1.5. Os outros levam o conteúdo, de
/// qualquer tamanho até o limite do agente; quem resume é o driver.
fn cabe(mecanismo: CK_MECHANISM_TYPE, dados: &[u8], bytes: usize) -> bool {
    match mecanismo {
        CKM_RSA_PKCS => !dados.is_empty() && dados.len() <= bytes.saturating_sub(11),
        _ => dados.len() <= LIMITE_DOS_DADOS,
    }
}

/// O fim comum de `C_Sign` (com `dados`) e `C_SignFinal` (com o acumulado).
///
/// A operação é tirada da sessão sob a trava, e a assinatura acontece sem
/// ela: pode levar o tempo de a pessoa digitar o OTP, e nesse tempo a mesma
/// aplicação continua listando tokens e abrindo sessões.
unsafe fn assinar_e_entregar(
    hSession: CK_SESSION_HANDLE,
    dados: Option<&[u8]>,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    let (operacao, token, chave, bytes) = {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let logado = modulo.logado();
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(operacao) = sessao.assinatura.as_ref() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let alvo = modulo.slot(sessao.slot).and_then(|slot| {
            let chave = slot.da_privada(operacao.chave)?;
            Some((slot.token.clone()?, chave.id.clone(), chave.bytes()))
        });
        let Some((token, chave, bytes)) = alvo else {
            modulo
                .sessoes
                .get_mut(&hSession)
                .expect("conferida")
                .assinatura = None;
            return CKR_KEY_HANDLE_INVALID;
        };
        if let Err(rv) = conferir_saida(bytes, pSignature, pulSignatureLen) {
            return rv;
        }
        let operacao = modulo
            .sessoes
            .get_mut(&hSession)
            .expect("conferida")
            .assinatura
            .take()
            .expect("conferida");
        if !logado {
            return CKR_USER_NOT_LOGGED_IN;
        }
        (operacao, token, chave, bytes)
    };
    let dados = dados.unwrap_or(&operacao.acumulado);
    let mut bloco = registro::impressao(dados);
    bloco["mecanismo"] = registro::mecanismo(operacao.mecanismo).into();
    registro::evento("bloco", bloco);
    if !cabe(operacao.mecanismo, dados, bytes) {
        return CKR_DATA_LEN_RANGE;
    }
    let Some(mecanismo) = slots::do_contrato(operacao.mecanismo) else {
        return CKR_MECHANISM_INVALID;
    };
    let inicio = Instant::now();
    let resposta = canal::pedir(&DaFace::Assinar {
        token,
        chave,
        mecanismo,
        dados: dados.to_vec(),
    });
    match resposta {
        Ok((DoAgente::Assinatura { assinatura }, _)) => {
            if let Some(modulo) = trava(&MODULO).as_mut() {
                modulo.usou(inicio);
            }
            entregar(&assinatura, bytes, pSignature, pulSignatureLen)
        }
        Ok((DoAgente::Falha { erro }, _)) => {
            // O tipo do erro e não a mensagem: a do token é texto livre.
            registro::evento("falha", json!({ "etapa": "assinar", "erro": erro.tipo }));
            let mut guarda = trava(&MODULO);
            if let Some(modulo) = guarda.as_mut() {
                match erro.tipo {
                    // A sessão no servidor venceu: o hospedeiro faz o C_Login
                    // de novo.
                    TipoDeFalha::NaoAutenticado => modulo.login = None,
                    TipoDeFalha::Bloqueado => {
                        modulo.login = None;
                        modulo.pin = SituacaoDoPin::Bloqueado;
                    }
                    _ => {}
                }
            }
            rv_da_falha(erro.tipo)
        }
        Ok(_) => CKR_FUNCTION_FAILED,
        Err(e) => {
            registro::evento(
                "falha",
                json!({ "etapa": "assinar", "erro": e.kind().to_string() }),
            );
            CKR_DEVICE_ERROR
        }
    }
}

/// Assinatura de uma parte só, a do poppler ao assinar PDF.
pub(crate) unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_Sign", {"sessao": hSession, "bytes": ulDataLen, "so_tamanho": pSignature.is_null()}, {
        match bloco_do_host(pData, ulDataLen) {
            Ok(dados) => assinar_e_entregar(hSession, Some(dados), pSignature, pulSignatureLen),
            Err(rv) => rv,
        }
    })
}

pub(crate) unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut CK_BYTE,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    entrada!("C_SignUpdate", {"sessao": hSession, "bytes": ulPartLen}, {
        let mut guarda = trava(&MODULO);
        let Some(sessao) = modulo!(guarda).sessoes.get_mut(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(operacao) = sessao.assinatura.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let pedaco = match bloco_do_host(pPart, ulPartLen) {
            Ok(pedaco) => pedaco,
            Err(rv) => return rv,
        };
        if operacao.acumulado.len() + pedaco.len() > LIMITE_DOS_DADOS {
            sessao.assinatura = None;
            return CKR_DATA_LEN_RANGE;
        }
        operacao.acumulado.extend_from_slice(pedaco);
        CKR_OK
    })
}

pub(crate) unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_SignFinal", {"sessao": hSession, "so_tamanho": pSignature.is_null()}, {
        assinar_e_entregar(hSession, None, pSignature, pulSignatureLen)
    })
}

/// Cifra com a chave pública do certificado. A privada é recusada: cifrar
/// com ela não é operação do PKCS#11 (o SunPKCS11 a transforma em
/// `C_SignInit` e `C_Sign`, e nunca chega aqui).
pub(crate) unsafe extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    entrada!("C_EncryptInit", {"sessao": hSession, "mecanismo": registro::mecanismo_de(pMechanism), "chave": hKey}, {
        iniciar(hSession, pMechanism, hKey, Uso::Cifrar)
    })
}

/// O `CKM_RSA_PKCS` é de uma parte só: `C_EncryptUpdate` e `C_EncryptFinal`
/// ficam sem suporte.
pub(crate) unsafe extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pEncryptedData: *mut CK_BYTE,
    pulEncryptedDataLen: *mut CK_ULONG,
) -> CK_RV {
    entrada!("C_Encrypt", {"sessao": hSession, "bytes": ulDataLen, "so_tamanho": pEncryptedData.is_null()}, {
        let mut guarda = trava(&MODULO);
        let modulo = modulo!(guarda);
        let Some(sessao) = modulo.sessoes.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(operacao) = sessao.cifra.as_ref() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let Some(publica) = modulo
            .slot(sessao.slot)
            .and_then(|s| s.da_publica(operacao.chave))
            .map(|c| c.publica.clone())
        else {
            return CKR_KEY_HANDLE_INVALID;
        };
        let bytes = rsa::traits::PublicKeyParts::size(&publica);
        if let Err(rv) = conferir_saida(bytes, pEncryptedData, pulEncryptedDataLen) {
            return rv;
        }
        modulo.sessoes.get_mut(&hSession).expect("conferida").cifra = None;
        let dados = match bloco_do_host(pData, ulDataLen) {
            Ok(d) if cabe(CKM_RSA_PKCS, d, bytes) => d,
            Ok(_) => return CKR_DATA_LEN_RANGE,
            Err(rv) => return rv,
        };
        let mut aleatorio = rand_core::UnwrapErr(getrandom::SysRng);
        match publica.encrypt(&mut aleatorio, Pkcs1v15Encrypt, dados) {
            Ok(cifrado) => entregar(&cifrado, bytes, pEncryptedData, pulEncryptedDataLen),
            Err(_) => CKR_FUNCTION_FAILED,
        }
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn campo_de_texto_e_completado_com_espaco_e_truncado() {
        let mut campo = [0u8; 8];
        preencher(&mut campo, "abc");
        assert_eq!(&campo, b"abc     ");
        let mut curto = [0u8; 4];
        preencher(&mut curto, "abcdefgh");
        assert_eq!(&curto, b"abcd");
        // O "ç" e o "ã" têm 2 bytes cada: cortar em 3 partiria o "ã".
        let mut acento = [0u8; 3];
        preencher(&mut acento, "ção");
        assert_eq!(&acento, "ç ".as_bytes());
    }

    #[test]
    fn o_rsa_pkcs_cabe_no_bloco_e_os_outros_no_limite() {
        assert!(cabe(CKM_RSA_PKCS, &[0x30; 51], 256));
        assert!(cabe(CKM_RSA_PKCS, &[0; 245], 256));
        assert!(!cabe(CKM_RSA_PKCS, &[0; 246], 256), "teto do PKCS#1 v1.5");
        assert!(!cabe(CKM_RSA_PKCS, &[], 256));
        assert!(cabe(CKM_SHA256_RSA_PKCS, &[], 256));
        assert!(cabe(CKM_SHA256_RSA_PKCS, &vec![0; LIMITE_DOS_DADOS], 256));
        assert!(!cabe(
            CKM_SHA256_RSA_PKCS,
            &vec![0; LIMITE_DOS_DADOS + 1],
            256
        ));
    }

    #[test]
    fn o_token_de_verdade_pede_login_e_mostra_o_pin_que_falta() {
        let vazio = Slot {
            id: 1,
            token: None,
            chaves: Vec::new(),
            objetos: Vec::new(),
        };
        assert_eq!(
            flags_do_token(&vazio, SituacaoDoPin::Normal) & CKF_LOGIN_REQUIRED,
            0
        );
        let token = Slot {
            token: Some("RemoteID".into()),
            ..vazio
        };
        let flags = flags_do_token(&token, SituacaoDoPin::Normal);
        assert_ne!(flags & CKF_LOGIN_REQUIRED, 0);
        assert_ne!(flags & CKF_USER_PIN_INITIALIZED, 0);
        let ultima = flags_do_token(&token, SituacaoDoPin::Restam(1));
        assert_ne!(ultima & CKF_USER_PIN_FINAL_TRY, 0);
        let bloqueado = flags_do_token(&token, SituacaoDoPin::Bloqueado);
        assert_ne!(bloqueado & CKF_USER_PIN_LOCKED, 0);
    }
}
