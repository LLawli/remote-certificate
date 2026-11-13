//! O PIN pessoal: quem está no dispositivo pareado.
//!
//! Ele nunca chega ao token. O servidor confere o PIN pessoal e só então usa
//! o fator guardado; o que sai daqui é um [`Autenticado`], que não carrega o
//! PIN. Errar [`ERROS_PARA_BLOQUEAR`] vezes seguidas bloqueia o dispositivo até
//! o administrador desbloquear, e o acerto zera o contador.

use std::fmt;
use std::sync::Mutex;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use protocolo::Segredo;

use crate::banco::{Banco, FalhaDoBanco, HashDoPin, IdDoDispositivo, IdDoUsuario, Reserva, travar};

pub const ERROS_PARA_BLOQUEAR: u32 = 3;
/// Em caracteres.
pub const TAMANHO_MINIMO: usize = 4;
pub const TAMANHO_MAXIMO: usize = 64;

/// A segunda opção recomendada da RFC 9106 (a primeira, de 2 GiB por
/// conferência, não cabe num servidor com logins simultâneos). Em KiB.
const MEMORIA: u32 = 64 * 1024;
const PASSADAS: u32 = 3;
const VIAS: u32 = 4;

fn argon2id() -> Argon2<'static> {
    let parametros =
        Params::new(MEMORIA, PASSADAS, VIAS, None).expect("parâmetros da RFC 9106 são válidos");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parametros)
}

/// A prova de que o PIN pessoal conferiu: só [`conferir`] cria uma.
#[derive(Debug)]
pub struct Autenticado {
    usuario: IdDoUsuario,
    dispositivo: IdDoDispositivo,
}

impl Autenticado {
    pub fn usuario(&self) -> IdDoUsuario {
        self.usuario
    }

    pub fn dispositivo(&self) -> IdDoDispositivo {
        self.dispositivo
    }

    #[cfg(test)]
    pub(crate) fn de_teste() -> Autenticado {
        Autenticado {
            usuario: IdDoUsuario(1),
            dispositivo: IdDoDispositivo(1),
        }
    }
}

#[derive(Debug)]
pub enum FalhaDoPin {
    /// Um PIN novo fora de [`TAMANHO_MINIMO`]..=[`TAMANHO_MAXIMO`].
    Tamanho,
    Errado {
        restantes: u32,
    },
    /// Até o administrador desbloquear. Bloqueado, nem o PIN certo passa.
    Bloqueado,
    DispositivoDesconhecido,
    Banco(FalhaDoBanco),
}

impl fmt::Display for FalhaDoPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoPin::Tamanho => write!(
                f,
                "o PIN pessoal tem que ter de {TAMANHO_MINIMO} a {TAMANHO_MAXIMO} caracteres"
            ),
            FalhaDoPin::Errado { restantes } => {
                write!(f, "PIN pessoal errado; {restantes} tentativas até bloquear")
            }
            FalhaDoPin::Bloqueado => {
                f.write_str("dispositivo bloqueado; o administrador desbloqueia")
            }
            FalhaDoPin::DispositivoDesconhecido => f.write_str("dispositivo desconhecido"),
            FalhaDoPin::Banco(falha) => falha.fmt(f),
        }
    }
}

impl From<FalhaDoBanco> for FalhaDoPin {
    fn from(falha: FalhaDoBanco) -> FalhaDoPin {
        FalhaDoPin::Banco(falha)
    }
}

/// O hash de um PIN novo, com sal aleatório. Os parâmetros ficam no próprio
/// hash: a conferência usa os dele, então subi-los não invalida os antigos.
pub fn hash(pin: &Segredo) -> Result<HashDoPin, FalhaDoPin> {
    let tamanho = pin.expor().chars().count();
    if !(TAMANHO_MINIMO..=TAMANHO_MAXIMO).contains(&tamanho) {
        return Err(FalhaDoPin::Tamanho);
    }
    let hash = argon2id()
        .hash_password(pin.expor().as_bytes())
        .expect("Argon2id com sal do sistema");
    Ok(HashDoPin(hash.to_string()))
}

/// Confere o PIN pessoal digitado no dispositivo. A tentativa é contada antes
/// da conferência, que roda sem o banco travado.
pub fn conferir(
    banco: &Mutex<Banco>,
    dispositivo: IdDoDispositivo,
    pin: &Segredo,
) -> Result<Autenticado, FalhaDoPin> {
    let reserva = travar(banco).reservar_tentativa(dispositivo, ERROS_PARA_BLOQUEAR)?;
    let (usuario, guardado, erros_seguidos) = match reserva {
        Reserva::Desconhecido => return Err(FalhaDoPin::DispositivoDesconhecido),
        Reserva::Bloqueado => return Err(FalhaDoPin::Bloqueado),
        Reserva::Contada {
            usuario,
            pin,
            erros_seguidos,
        } => (usuario, pin, erros_seguidos),
    };
    // Um hash ilegível no banco falha fechado, como um PIN errado.
    let certo = PasswordHash::new(guardado.como_texto()).is_ok_and(|h| {
        argon2id()
            .verify_password(pin.expor().as_bytes(), &h)
            .is_ok()
    });
    if certo {
        travar(banco).zerar_erros(dispositivo)?;
        return Ok(Autenticado {
            usuario,
            dispositivo,
        });
    }
    match ERROS_PARA_BLOQUEAR.saturating_sub(erros_seguidos) {
        0 => Err(FalhaDoPin::Bloqueado),
        restantes => Err(FalhaDoPin::Errado { restantes }),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_hash_e_argon2id_e_nao_traz_o_pin() {
        let pin = Segredo::novo("2468-pessoal".into());
        let hash = hash(&pin).unwrap();
        assert!(
            hash.como_texto()
                .starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "{hash:?}"
        );
        assert!(!hash.como_texto().contains("2468"));
        assert_ne!(hash, super::hash(&pin).unwrap(), "o sal muda a cada hash");
    }

    #[test]
    fn pin_fora_do_tamanho_e_recusado() {
        for pin in ["123", &"9".repeat(TAMANHO_MAXIMO + 1)] {
            let falha = hash(&Segredo::novo(pin.to_string()));
            assert!(matches!(falha, Err(FalhaDoPin::Tamanho)), "{pin}");
        }
        assert!(hash(&Segredo::novo("1234".into())).is_ok());
    }
}
