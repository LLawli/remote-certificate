//! O serviço. Por enquanto só se apresenta: o desenho está em
//! `docs/arquitetura.md`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let versao = env!("CARGO_PKG_VERSION");
    match std::env::args().nth(1).as_deref() {
        Some("versao" | "--version") => {
            println!(
                "remote-certificate {versao} (contrato de driver v{})",
                protocolo::VERSAO
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("remote-certificate {versao}: em construção, ver docs/arquitetura.md");
            ExitCode::FAILURE
        }
    }
}
