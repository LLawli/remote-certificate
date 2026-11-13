//! O serviço. Por enquanto, os comandos de quem opera: o backup e o código de
//! recuperação. O desenho está em `docs/arquitetura.md`.

use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use servidor::banco::{BANCO_PADRAO, Banco, CHAVE_PADRAO, ler_chave};
use servidor::recuperacao::{self, CodigoInvalido};
use zeroize::Zeroizing;

const USO: &str = "\
uso: remote-certificate <comando>

  versao
  backup <destino> [--banco <arquivo>] [--chave <arquivo>]
                     copia o banco com o serviço rodando e confere a cópia
  recuperacao mostrar [--chave <arquivo>]
                     mostra o código de recuperação da chave do banco, uma vez
  recuperacao restaurar
                     lê o código no stdin e escreve a chave no stdout";

/// Limpa a tela e o histórico do terminal, para o código não ficar ali.
const LIMPAR_TERMINAL: &str = "\x1b[2J\x1b[3J\x1b[H";

fn main() -> ExitCode {
    if let Err(e) = memoria::endurecer_processo() {
        eprintln!("remote-certificate: não deu para proteger o processo: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
    let resultado = match args.as_slice() {
        ["versao" | "--version"] => {
            println!(
                "remote-certificate {} (contrato de driver v{})",
                env!("CARGO_PKG_VERSION"),
                protocolo::VERSAO
            );
            Ok(())
        }
        ["backup", destino, resto @ ..] => backup(destino, resto),
        ["recuperacao", "mostrar", resto @ ..] => mostrar(resto),
        ["recuperacao", "restaurar"] => restaurar(),
        _ => Err(USO.to_string()),
    };
    match resultado {
        Ok(()) => ExitCode::SUCCESS,
        Err(mensagem) => {
            eprintln!("{mensagem}");
            ExitCode::FAILURE
        }
    }
}

/// O valor de `--nome` nas opções, ou o padrão.
fn opcao(resto: &[&str], nome: &str, padrao: &str) -> Result<PathBuf, String> {
    let mut valor = padrao;
    let mut opcoes = resto.iter();
    while let Some(opcao) = opcoes.next() {
        match (*opcao, opcoes.next()) {
            (o, Some(v)) if o == nome => valor = v,
            (o, Some(_)) if o.starts_with("--") => {}
            _ => return Err(USO.to_string()),
        }
    }
    Ok(PathBuf::from(valor))
}

fn backup(destino: &str, resto: &[&str]) -> Result<(), String> {
    let chave = ler_chave(&opcao(resto, "--chave", CHAVE_PADRAO)?).map_err(|e| e.to_string())?;
    let banco =
        Banco::abrir(&opcao(resto, "--banco", BANCO_PADRAO)?, chave).map_err(|e| e.to_string())?;
    banco
        .backup(&PathBuf::from(destino))
        .map_err(|e| e.to_string())?;
    println!("backup conferido: {destino}");
    Ok(())
}

fn mostrar(resto: &[&str]) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        return Err("o código de recuperação só aparece num terminal".into());
    }
    let chave = ler_chave(&opcao(resto, "--chave", CHAVE_PADRAO)?).map_err(|e| e.to_string())?;
    let codigo = recuperacao::codigo(&chave);
    println!(
        "Código de recuperação da chave do banco:\n\n  {}\n",
        codigo.as_str()
    );
    println!("Guarde fora desta máquina (num gerenciador de senhas, por exemplo).");
    print!("Digite o código de volta para conferir: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let digitado = ler_linha()?;
    print!("{LIMPAR_TERMINAL}");
    match recuperacao::chave(&digitado) {
        Ok(lida) if lida.expor() == chave.expor() => {
            println!("Código conferido.");
            Ok(())
        }
        Ok(_) | Err(CodigoInvalido::Conferencia) => {
            Err("o código digitado não confere; rode de novo".into())
        }
        Err(CodigoInvalido::Formato) => Err("isso não é um código de recuperação".into()),
    }
}

fn restaurar() -> Result<(), String> {
    let mut saida = io::stdout();
    if saida.is_terminal() {
        return Err("a chave é binária: mande o stdout para um arquivo ou um programa".into());
    }
    if io::stdin().is_terminal() {
        eprint!("Código de recuperação: ");
    }
    let chave = recuperacao::chave(&ler_linha()?).map_err(|e| match e {
        CodigoInvalido::Conferencia => "o código não confere: confira cada grupo".to_string(),
        CodigoInvalido::Formato => "isso não é um código de recuperação".to_string(),
    })?;
    saida
        .write_all(chave.expor())
        .and_then(|()| saida.flush())
        .map_err(|e| e.to_string())
}

fn ler_linha() -> Result<Zeroizing<String>, String> {
    let mut linha = Zeroizing::new(String::new());
    io::stdin()
        .lock()
        .read_line(&mut linha)
        .map_err(|e| e.to_string())?;
    Ok(linha)
}
