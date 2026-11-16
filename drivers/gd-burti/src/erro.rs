//! A tradução das falhas do PKCS#11 para os tipos de erro do contrato.
//!
//! O tipo é o que o servidor usa para decidir; a mensagem é para a pessoa e
//! leva o código do PKCS#11, nunca o PIN.

use cryptoki::error::{Error as ErroPkcs11, RvError};
use protocolo::{Erro, TipoDeErro};

pub fn erro(tipo: TipoDeErro, mensagem: impl Into<String>) -> Erro {
    Erro {
        tipo,
        mensagem: mensagem.into(),
    }
}

/// O tipo do contrato para um código de retorno do PKCS#11.
pub fn tipo_do_rv(rv: RvError) -> TipoDeErro {
    use RvError::*;
    match rv {
        // O PIN guardado não confere: o servidor para o token e não tenta de
        // novo. `PinLenRange` e `PinInvalid` também são um PIN que o token
        // recusou, só que antes de gastar uma tentativa.
        PinIncorrect | PinInvalid | PinLenRange => TipoDeErro::FatorRecusado,
        // O token travou o PIN (ou exige trocá-lo): só o administrador
        // destrava, no Token Administration.
        PinLocked | PinExpired => TipoDeErro::Bloqueado,
        TokenNotPresent | TokenNotRecognized | DeviceRemoved | DeviceError | SlotIdInvalid
        | SessionHandleInvalid | SessionClosed => TipoDeErro::TokenAusente,
        MechanismInvalid
        | MechanismParamInvalid
        | KeyTypeInconsistent
        | KeyFunctionNotPermitted
        | KeySizeRange => TipoDeErro::MecanismoNaoSuportado,
        KeyHandleInvalid | ObjectHandleInvalid => TipoDeErro::ChaveAusente,
        DataInvalid | DataLenRange => TipoDeErro::PedidoInvalido,
        FunctionCanceled | Cancel => TipoDeErro::Cancelado,
        _ => TipoDeErro::Outro,
    }
}

fn mensagem_do_tipo(tipo: TipoDeErro) -> &'static str {
    match tipo {
        TipoDeErro::FatorRecusado => "O token recusou o PIN guardado",
        TipoDeErro::Bloqueado => {
            "O PIN do token está bloqueado; desbloqueie no Token Administration"
        }
        TipoDeErro::TokenAusente => "O token GD Burti não está acessível",
        TipoDeErro::MecanismoNaoSuportado => "O token não assina com esse mecanismo",
        TipoDeErro::ChaveAusente => "A chave não está no token",
        TipoDeErro::PedidoInvalido => "O token recusou os dados",
        TipoDeErro::Cancelado => "Operação cancelada",
        _ => "Falha no módulo PKCS#11 do SafeSign",
    }
}

/// Uma falha do `cryptoki` no contrato. `onde` diz o que o driver fazia.
pub fn traduzir(onde: &str, falha: ErroPkcs11) -> Erro {
    match falha {
        ErroPkcs11::Pkcs11(rv, funcao) => {
            let tipo = tipo_do_rv(rv);
            erro(
                tipo,
                format!(
                    "{} ({onde}: {funcao:?} devolveu {rv:?})",
                    mensagem_do_tipo(tipo)
                ),
            )
        }
        ErroPkcs11::LibraryLoading(e) => erro(
            TipoDeErro::Outro,
            format!("O módulo PKCS#11 do SafeSign não carregou ({onde}): {e}"),
        ),
        outra => erro(
            TipoDeErro::Outro,
            format!("Falha no módulo PKCS#11 do SafeSign ({onde}): {outra}"),
        ),
    }
}

#[cfg(test)]
mod testes {
    use cryptoki::context::Function;

    use super::*;

    #[test]
    fn pin_errado_e_fator_recusado() {
        for rv in [
            RvError::PinIncorrect,
            RvError::PinInvalid,
            RvError::PinLenRange,
        ] {
            assert_eq!(tipo_do_rv(rv), TipoDeErro::FatorRecusado, "{rv:?}");
        }
    }

    #[test]
    fn pin_travado_e_bloqueado() {
        assert_eq!(tipo_do_rv(RvError::PinLocked), TipoDeErro::Bloqueado);
        assert_eq!(tipo_do_rv(RvError::PinExpired), TipoDeErro::Bloqueado);
    }

    #[test]
    fn token_removido_e_token_ausente() {
        for rv in [
            RvError::TokenNotPresent,
            RvError::DeviceRemoved,
            RvError::SessionHandleInvalid,
        ] {
            assert_eq!(tipo_do_rv(rv), TipoDeErro::TokenAusente, "{rv:?}");
        }
    }

    #[test]
    fn o_resto_vira_outro_com_o_codigo_na_mensagem() {
        let falha = traduzir(
            "assinar",
            ErroPkcs11::Pkcs11(RvError::GeneralError, Function::Sign),
        );
        assert_eq!(falha.tipo, TipoDeErro::Outro);
        assert!(
            falha.mensagem.contains("GeneralError"),
            "{}",
            falha.mensagem
        );
    }

    #[test]
    fn a_mensagem_do_pin_recusado_diz_o_codigo() {
        let falha = traduzir(
            "login",
            ErroPkcs11::Pkcs11(RvError::PinIncorrect, Function::Login),
        );
        assert_eq!(falha.tipo, TipoDeErro::FatorRecusado);
        assert!(
            falha.mensagem.contains("PinIncorrect"),
            "{}",
            falha.mensagem
        );
    }
}
