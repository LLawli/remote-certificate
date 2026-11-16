//! Driver dos tokens A3 GD Burti para o remote-certificate.
//!
//! Fala o contrato de `docs/drivers.md` pelo stdin e pelo stdout e usa o
//! módulo PKCS#11 oficial do SafeSign IC (`libaetpkss.so`) para chegar ao
//! token. Log vai para o stderr, e nunca leva o PIN.
//!
//! Argumentos (os da configuração do token no servidor):
//!
//! - `--modulo <caminho>`: o módulo PKCS#11. Padrão: o que a imagem instala,
//!   [`MODULO_PADRAO`].

use std::ffi::{OsStr, OsString};
use std::io::{self, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod conversa;
mod erro;
mod estado;
mod mecanismos;
mod token;

/// Onde o Dockerfile do driver põe o módulo do SafeSign.
const MODULO_PADRAO: &str = "/usr/lib/libaetpkss.so.3";

/// Marca a partida que já veio com o `HOME` no diretório de estado.
const REEXECUTADO: &str = "GD_BURTI_HOME_NO_ESTADO";

fn ler_argumentos(argumentos: impl IntoIterator<Item = OsString>) -> Result<PathBuf, String> {
    let mut modulo = PathBuf::from(MODULO_PADRAO);
    let mut argumentos = argumentos.into_iter();
    while let Some(argumento) = argumentos.next() {
        match argumento.to_str() {
            Some("--modulo") => {
                modulo = argumentos
                    .next()
                    .map(PathBuf::from)
                    .ok_or("--modulo pede o caminho do módulo")?;
            }
            _ => return Err(format!("argumento desconhecido: {argumento:?}")),
        }
    }
    Ok(modulo)
}

/// O SafeSign grava o próprio registro em `$HOME/.safesign`. O `HOME` do
/// servidor não é gravável pelo driver isolado, e nem deveria juntar o estado
/// de tokens diferentes: o driver se executa de novo com o `HOME` no diretório
/// de estado do token, antes de carregar o módulo.
fn precisa_de_outro_home(home: Option<&OsStr>, estado: &Path, ja_reexecutado: bool) -> bool {
    !ja_reexecutado && home.map(Path::new) != Some(estado)
}

fn main() -> ExitCode {
    let estado = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("gd-burti: sem diretório de trabalho: {e}");
            return ExitCode::FAILURE;
        }
    };
    if precisa_de_outro_home(
        std::env::var_os("HOME").as_deref(),
        &estado,
        std::env::var_os(REEXECUTADO).is_some(),
    ) {
        match std::env::current_exe() {
            Ok(executavel) => {
                let falha = Command::new(executavel)
                    .args(std::env::args_os().skip(1))
                    .env("HOME", &estado)
                    .env(REEXECUTADO, "1")
                    .exec();
                eprintln!("gd-burti: não deu para pôr o HOME no estado ({falha}); sigo sem");
            }
            Err(e) => eprintln!("gd-burti: não achei o próprio executável ({e}); sigo sem"),
        }
    }
    // Fora de core dump e do ptrace de outros processos do mesmo usuário: o
    // PIN passa pela memória deste processo. O `execve` volta o valor para 1,
    // por isso vem depois da troca do HOME.
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        eprintln!("gd-burti: PR_SET_DUMPABLE falhou: {e}");
        return ExitCode::FAILURE;
    }
    let modulo = match ler_argumentos(std::env::args_os().skip(1)) {
        Ok(modulo) => modulo,
        Err(e) => {
            eprintln!("gd-burti: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut driver =
        conversa::Driver::novo(token::SafeSign::novo(modulo), estado::Estado::em(estado));
    let mut entrada = BufReader::new(io::stdin().lock());
    let mut saida = io::stdout().lock();
    match driver.conversar(&mut entrada, &mut saida) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gd-burti: conversa encerrada: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn modulo_padrao_e_o_da_imagem() {
        assert_eq!(
            ler_argumentos(Vec::<OsString>::new()).unwrap(),
            Path::new(MODULO_PADRAO)
        );
        assert_eq!(
            ler_argumentos(["--modulo".into(), "/x/libsofthsm2.so".into()]).unwrap(),
            Path::new("/x/libsofthsm2.so")
        );
        assert!(ler_argumentos(["--modulo".into()]).is_err());
        assert!(ler_argumentos(["--pin".into(), "1234".into()]).is_err());
    }

    #[test]
    fn home_vai_para_o_estado_uma_vez() {
        let estado = Path::new("/dados/drivers/1");
        assert!(precisa_de_outro_home(
            Some(OsStr::new("/dados")),
            estado,
            false
        ));
        assert!(precisa_de_outro_home(None, estado, false));
        assert!(!precisa_de_outro_home(
            Some(estado.as_os_str()),
            estado,
            false
        ));
        // Uma segunda partida não entra em laço, mesmo que o HOME não pegue.
        assert!(!precisa_de_outro_home(
            Some(OsStr::new("/dados")),
            estado,
            true
        ));
    }
}
