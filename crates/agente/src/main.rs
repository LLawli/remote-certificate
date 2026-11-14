//! O agente da estação, como a pessoa (ou o instalador) o usa.

use std::ffi::OsString;
use std::io::{self, BufRead};
use std::process::ExitCode;
use std::sync::Arc;

use agente::cofre::{Cofre, CofreEmArquivo};
use agente::dialogo::DialogoExterno;
use agente::{Agente, novo_pareamento};
use zeroize::Zeroizing;

const USO: &str = "\
uso: remote-certificate-agente <comando>

  parear <endereco>  pareia este computador com o servidor em <ip:porta>;
                     o código que o administrador gerou vem do stdin
  servir             atende os programas deste usuário (o módulo PKCS#11)
  estado             mostra com qual servidor este computador está pareado
  esquecer           apaga o pareamento e a chave deste computador";

fn main() -> ExitCode {
    if let Err(e) = memoria::endurecer_processo() {
        eprintln!("remote-certificate-agente: não deu para proteger o processo: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
    let resultado = match args.as_slice() {
        ["parear", endereco] => parear(endereco),
        ["servir"] => servir(),
        ["estado"] => estado(),
        ["esquecer"] => esquecer(),
        _ => {
            eprintln!("{USO}");
            return ExitCode::from(2);
        }
    };
    match resultado {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("remote-certificate-agente: {e}");
            ExitCode::FAILURE
        }
    }
}

type Resultado = Result<(), Box<dyn std::error::Error>>;

fn execucao() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn parear(endereco: &str) -> Resultado {
    let cofre = CofreEmArquivo::padrao()?;
    if cofre.ler()?.is_some() {
        return Err(format!(
            "este computador já está pareado ({}); rode `esquecer` antes de parear de novo",
            cofre.arquivo().display()
        )
        .into());
    }
    let mut codigo = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut codigo)?;
    let pareamento = execucao()?
        .block_on(novo_pareamento(endereco, codigo.trim()))
        .map_err(|e| e.to_string())?;
    cofre.gravar(&pareamento)?;
    println!(
        "pareado com {}: este computador é o dispositivo {}",
        pareamento.endereco, pareamento.dispositivo
    );
    Ok(())
}

fn servir() -> Resultado {
    let pareamento = CofreEmArquivo::padrao()?
        .ler()?
        .ok_or("este computador não está pareado: rode `parear` antes")?;
    let caminho = ipc::caminho_do_socket().ok_or("sem XDG_RUNTIME_DIR para o socket")?;
    let agente = Agente::novo(pareamento, Arc::new(DialogoExterno::padrao()));
    execucao()?.block_on(agente::unix::ouvir(agente, &caminho))?;
    Ok(())
}

fn estado() -> Resultado {
    match CofreEmArquivo::padrao()?.ler()? {
        Some(pareamento) => println!(
            "pareado com {} como o dispositivo {}",
            pareamento.endereco, pareamento.dispositivo
        ),
        None => println!("não pareado"),
    }
    Ok(())
}

fn esquecer() -> Resultado {
    let cofre = CofreEmArquivo::padrao()?;
    cofre.esquecer()?;
    println!("pareamento apagado; o administrador revoga o dispositivo no servidor");
    Ok(())
}
