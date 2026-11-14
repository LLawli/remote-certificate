//! As funções da tabela que estes tokens não fazem (portado do
//! RemoteID-linux). Nenhum ponteiro da tabela pode ser nulo, porque o p11-kit
//! e o NSS chamam sem conferir; estas devolvem `CKR_FUNCTION_NOT_SUPPORTED`,
//! como a especificação manda.

use cryptoki_sys::*;

macro_rules! nao_suportadas {
    ($($nome:ident($($tipo:ty),*);)*) => {
        $(
            pub(crate) extern "C" fn $nome($(_: $tipo),*) -> CK_RV {
                // Vai ao registro: é o que diz o que o hospedeiro esperava.
                crate::registro::chamada(
                    stringify!($nome),
                    serde_json::json!({}),
                    || CKR_FUNCTION_NOT_SUPPORTED,
                )
            }
        )*
    };
}

nao_suportadas! {
    C_InitToken(CK_SLOT_ID, *mut CK_UTF8CHAR, CK_ULONG, *mut CK_UTF8CHAR);
    C_InitPIN(CK_SESSION_HANDLE, *mut CK_UTF8CHAR, CK_ULONG);
    C_SetPIN(CK_SESSION_HANDLE, *mut CK_UTF8CHAR, CK_ULONG, *mut CK_UTF8CHAR, CK_ULONG);
    C_GetOperationState(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG);
    C_SetOperationState(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    C_CreateObject(CK_SESSION_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE);
    C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE);
    C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    C_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ULONG);
    C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG);
    C_EncryptUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_EncryptFinal(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG);
    C_DecryptInit(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE);
    C_Decrypt(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DecryptUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DecryptFinal(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG);
    C_DigestInit(CK_SESSION_HANDLE, *mut CK_MECHANISM);
    C_Digest(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DigestUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG);
    C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    C_DigestFinal(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG);
    C_SignRecoverInit(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE);
    C_SignRecover(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_VerifyInit(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE);
    C_Verify(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, CK_ULONG);
    C_VerifyUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG);
    C_VerifyFinal(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG);
    C_VerifyRecoverInit(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE);
    C_VerifyRecover(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DigestEncryptUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DecryptDigestUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_SignEncryptUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_DecryptVerifyUpdate(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG);
    C_GenerateKey(CK_SESSION_HANDLE, *mut CK_MECHANISM, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE);
    C_GenerateKeyPair(CK_SESSION_HANDLE, *mut CK_MECHANISM, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE, *mut CK_OBJECT_HANDLE);
    C_WrapKey(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, *mut CK_BYTE, *mut CK_ULONG);
    C_UnwrapKey(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE, *mut CK_BYTE, CK_ULONG, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE);
    C_DeriveKey(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE);
    C_SeedRandom(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG);
    C_GenerateRandom(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG);
    C_GetFunctionStatus(CK_SESSION_HANDLE);
    C_CancelFunction(CK_SESSION_HANDLE);
    C_WaitForSlotEvent(CK_FLAGS, *mut CK_SLOT_ID, *mut std::ffi::c_void);
}
