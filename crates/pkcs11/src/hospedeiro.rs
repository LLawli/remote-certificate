//! O lado do hospedeiro, para os testes de integração dos drivers: as
//! chamadas que o NSS faz, pelos ponteiros da `CK_FUNCTION_LIST` e em duas
//! passadas onde a especificação manda. Só com a feature `hospedeiro`.
//!
//! Cada função confere o `CKR_OK` do que não é o objeto do teste e devolve o
//! `CK_RV` do que é.

// Os argumentos do `chamar!` ficam dentro do `unsafe` de propósito: são os
// ponteiros crus que o teste monta, como um hospedeiro C faria.
#![allow(clippy::macro_metavars_in_unsafe)]

use std::ptr;

use cryptoki_sys::*;

/// Chama uma função da tabela: `chamar!(C_Login(sessao, ...))`.
///
#[macro_export]
macro_rules! chamar {
    ($nome:ident($($arg:expr),* $(,)?)) => {
        unsafe {
            ($crate::hospedeiro::funcoes().$nome.expect(stringify!($nome)))($($arg),*)
        }
    };
}

pub fn funcoes() -> &'static CK_FUNCTION_LIST {
    let mut lista = ptr::null_mut();
    let rv = unsafe { crate::C_GetFunctionList(&mut lista) };
    assert_eq!(rv, CKR_OK);
    unsafe { &*lista }
}

pub fn slots() -> Vec<CK_SLOT_ID> {
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_GetSlotList(CK_TRUE, ptr::null_mut(), &mut n)),
        CKR_OK
    );
    let mut lista = vec![0; n as usize];
    assert_eq!(
        chamar!(C_GetSlotList(CK_TRUE, lista.as_mut_ptr(), &mut n)),
        CKR_OK
    );
    lista
}

pub fn info_do_token(slot: CK_SLOT_ID) -> CK_TOKEN_INFO {
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    assert_eq!(chamar!(C_GetTokenInfo(slot, &mut info)), CKR_OK);
    info
}

pub fn mecanismos(slot: CK_SLOT_ID) -> Vec<CK_MECHANISM_TYPE> {
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_GetMechanismList(slot, ptr::null_mut(), &mut n)),
        CKR_OK
    );
    let mut lista = vec![0; n as usize];
    assert_eq!(
        chamar!(C_GetMechanismList(slot, lista.as_mut_ptr(), &mut n)),
        CKR_OK
    );
    lista
}

pub fn info_do_mecanismo(
    slot: CK_SLOT_ID,
    mecanismo: CK_MECHANISM_TYPE,
) -> Result<CK_MECHANISM_INFO, CK_RV> {
    let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
    match chamar!(C_GetMechanismInfo(slot, mecanismo, &mut info)) {
        CKR_OK => Ok(info),
        rv => Err(rv),
    }
}

pub fn abrir_sessao(slot: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut sessao = 0;
    assert_eq!(
        chamar!(C_OpenSession(
            slot,
            CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut sessao
        )),
        CKR_OK
    );
    sessao
}

pub fn buscar(sessao: CK_SESSION_HANDLE, classe: CK_OBJECT_CLASS) -> Vec<CK_OBJECT_HANDLE> {
    let mut valor = classe;
    let mut gabarito = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut valor).cast(),
        ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    }];
    assert_eq!(
        chamar!(C_FindObjectsInit(sessao, gabarito.as_mut_ptr(), 1)),
        CKR_OK
    );
    let mut achados = [0; 16];
    let mut n: CK_ULONG = 0;
    assert_eq!(
        chamar!(C_FindObjects(sessao, achados.as_mut_ptr(), 16, &mut n)),
        CKR_OK
    );
    assert_eq!(chamar!(C_FindObjectsFinal(sessao)), CKR_OK);
    achados[..n as usize].to_vec()
}

/// Um atributo em duas passadas, como manda a especificação.
pub fn atributo(
    sessao: CK_SESSION_HANDLE,
    objeto: CK_OBJECT_HANDLE,
    tipo: CK_ATTRIBUTE_TYPE,
) -> Vec<u8> {
    let mut modelo = [CK_ATTRIBUTE {
        type_: tipo,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    }];
    assert_eq!(
        chamar!(C_GetAttributeValue(sessao, objeto, modelo.as_mut_ptr(), 1)),
        CKR_OK
    );
    let mut valor = vec![0u8; modelo[0].ulValueLen as usize];
    modelo[0].pValue = valor.as_mut_ptr().cast();
    assert_eq!(
        chamar!(C_GetAttributeValue(sessao, objeto, modelo.as_mut_ptr(), 1)),
        CKR_OK
    );
    valor
}

pub fn entrar(sessao: CK_SESSION_HANDLE, pin: &str) -> CK_RV {
    let mut pin = pin.as_bytes().to_vec();
    chamar!(C_Login(
        sessao,
        CKU_USER,
        pin.as_mut_ptr(),
        pin.len() as CK_ULONG
    ))
}

/// `C_SignInit` sem parâmetro.
pub fn iniciar(
    sessao: CK_SESSION_HANDLE,
    mecanismo: CK_MECHANISM_TYPE,
    chave: CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut mecanismo = CK_MECHANISM {
        mechanism: mecanismo,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    chamar!(C_SignInit(sessao, &mut mecanismo, chave))
}

/// `C_SignInit` de `mecanismo` com os parâmetros de um RSA-PSS, como o NSS
/// os passa no TLS 1.3.
pub fn iniciar_com_pss(
    sessao: CK_SESSION_HANDLE,
    mecanismo: CK_MECHANISM_TYPE,
    mut parametros: CK_RSA_PKCS_PSS_PARAMS,
    chave: CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut mecanismo = CK_MECHANISM {
        mechanism: mecanismo,
        pParameter: (&raw mut parametros).cast(),
        ulParameterLen: size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };
    chamar!(C_SignInit(sessao, &mut mecanismo, chave))
}

/// `C_Sign` em duas passadas: primeiro o tamanho, depois a assinatura.
pub fn assinar(sessao: CK_SESSION_HANDLE, dados: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let mut dados = dados.to_vec();
    let mut n: CK_ULONG = 0;
    let rv = chamar!(C_Sign(
        sessao,
        dados.as_mut_ptr(),
        dados.len() as CK_ULONG,
        ptr::null_mut(),
        &mut n
    ));
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut assinatura = vec![0u8; n as usize];
    let rv = chamar!(C_Sign(
        sessao,
        dados.as_mut_ptr(),
        dados.len() as CK_ULONG,
        assinatura.as_mut_ptr(),
        &mut n
    ));
    if rv != CKR_OK {
        return Err(rv);
    }
    assinatura.truncate(n as usize);
    Ok(assinatura)
}
