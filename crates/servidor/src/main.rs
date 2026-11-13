//! O serviço. Por enquanto, os comandos de quem opera: o backup, o código de
//! recuperação, os usuários e os dispositivos. O desenho está em
//! `docs/arquitetura.md`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};

use protocolo::Segredo;
use rustix::termios::{self, LocalModes, OptionalActions};
use servidor::banco::{BANCO_PADRAO, Banco, CHAVE_PADRAO, IdDoDispositivo, ler_chave, travar};
use servidor::driver::{Conversa, Driver};
use servidor::pin::{self, ERROS_PARA_BLOQUEAR};
use servidor::recuperacao::{self, CodigoInvalido};
use servidor::servico::{self, ENDERECO_PADRAO, Estado, VALIDADE_DO_PAREAMENTO};
use servidor::token::{GuardaNoBanco, Token};
use servidor::tokens::DRIVERS_PADRAO;
use zeroize::Zeroizing;

const USO: &str = "\
uso: remote-certificate <comando>

  versao
  servir [--endereco <ip:porta>] [--drivers <dir>] [--banco <arquivo>] [--chave <arquivo>]
  token criar <nome> <driver> [--banco <arquivo>] [--chave <arquivo>] [-- <argumentos do driver>]
  token configurar <nome>  [--drivers <dir>] [--banco <arquivo>] [--chave <arquivo>]
                     pergunta o que o driver pede (os segredos sem eco)
  token listar             [--banco <arquivo>] [--chave <arquivo>]
  backup <destino> [--banco <arquivo>] [--chave <arquivo>]
                     copia o banco com o serviço rodando e confere a cópia
  recuperacao mostrar [--chave <arquivo>]
                     mostra o código de recuperação da chave do banco, uma vez
  recuperacao restaurar
                     lê o código no stdin e escreve a chave no stdout
  usuario criar <nome>     [--banco <arquivo>] [--chave <arquivo>]
  usuario pin <nome>       [--banco <arquivo>] [--chave <arquivo>]
                     o PIN pessoal vem do stdin (pedido duas vezes num terminal)
  dispositivo parear <usuario> <nome> [--banco <arquivo>] [--chave <arquivo>]
                     mostra um código de pareamento de uso único
  dispositivo listar       [--banco <arquivo>] [--chave <arquivo>]
  dispositivo desbloquear <id> [--banco <arquivo>] [--chave <arquivo>]
  dispositivo revogar <id> [--banco <arquivo>] [--chave <arquivo>]";

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
        ["servir", resto @ ..] => servir(resto),
        ["backup", destino, resto @ ..] => backup(destino, resto),
        ["recuperacao", "mostrar", resto @ ..] => mostrar(resto),
        ["recuperacao", "restaurar"] => restaurar(),
        ["usuario", "criar", nome, resto @ ..] => criar_usuario(nome, resto),
        ["usuario", "pin", nome, resto @ ..] => trocar_pin(nome, resto),
        ["dispositivo", "parear", usuario, nome, resto @ ..] => parear(usuario, nome, resto),
        ["dispositivo", "listar", resto @ ..] => listar_dispositivos(resto),
        ["dispositivo", "desbloquear", id, resto @ ..] => desbloquear(id, resto),
        ["dispositivo", "revogar", id, resto @ ..] => revogar(id, resto),
        ["token", "criar", nome, driver, resto @ ..] => criar_token(nome, driver, resto),
        ["token", "configurar", nome, resto @ ..] => configurar_token(nome, resto),
        ["token", "listar", resto @ ..] => listar_tokens(resto),
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
fn opcao<'a>(resto: &[&'a str], nome: &str, padrao: &'a str) -> Result<&'a str, String> {
    let mut valor = padrao;
    let mut opcoes = resto.iter();
    while let Some(opcao) = opcoes.next() {
        match (*opcao, opcoes.next()) {
            (o, Some(v)) if o == nome => valor = v,
            (o, Some(_)) if o.starts_with("--") => {}
            _ => return Err(USO.to_string()),
        }
    }
    Ok(valor)
}

/// O banco de `--banco`, aberto com a chave de `--chave`.
fn abrir(resto: &[&str]) -> Result<Banco, String> {
    let chave =
        ler_chave(Path::new(opcao(resto, "--chave", CHAVE_PADRAO)?)).map_err(|e| e.to_string())?;
    Banco::abrir(Path::new(opcao(resto, "--banco", BANCO_PADRAO)?), chave)
        .map_err(|e| e.to_string())
}

fn servir(resto: &[&str]) -> Result<(), String> {
    let endereco = opcao(resto, "--endereco", ENDERECO_PADRAO)?;
    let drivers = Path::new(opcao(resto, "--drivers", DRIVERS_PADRAO)?);
    let banco = Arc::new(Mutex::new(abrir(resto)?));
    let execucao = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let estado = Estado::iniciar(banco, drivers).map_err(|e| e.to_string())?;
    execucao.block_on(async {
        let ouvinte = tokio::net::TcpListener::bind(endereco)
            .await
            .map_err(|e| format!("{endereco}: {e}"))?;
        eprintln!("remote-certificate atendendo em {endereco}");
        servico::servir(ouvinte, estado)
            .await
            .map_err(|e| e.to_string())
    })
}

fn parear(usuario: &str, nome: &str, resto: &[&str]) -> Result<(), String> {
    let banco = Mutex::new(abrir(resto)?);
    let id = travar(&banco)
        .usuario(usuario)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("não há usuário {usuario}"))?;
    let codigo = servico::novo_pareamento(&banco, id, nome).map_err(|e| e.to_string())?;
    println!("{}", codigo.as_str());
    eprintln!(
        "vale uma vez, por {} minutos",
        VALIDADE_DO_PAREAMENTO.as_secs() / 60
    );
    Ok(())
}

fn backup(destino: &str, resto: &[&str]) -> Result<(), String> {
    abrir(resto)?
        .backup(&PathBuf::from(destino))
        .map_err(|e| e.to_string())?;
    println!("backup conferido: {destino}");
    Ok(())
}

fn mostrar(resto: &[&str]) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        return Err("o código de recuperação só aparece num terminal".into());
    }
    let chave =
        ler_chave(Path::new(opcao(resto, "--chave", CHAVE_PADRAO)?)).map_err(|e| e.to_string())?;
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

fn criar_usuario(nome: &str, resto: &[&str]) -> Result<(), String> {
    let banco = abrir(resto)?;
    if banco.usuario(nome).map_err(|e| e.to_string())?.is_some() {
        return Err(format!("o usuário {nome} já existe"));
    }
    let hash = pin::hash(&ler_pin()?).map_err(|e| e.to_string())?;
    banco
        .criar_usuario(nome, &hash)
        .map_err(|e| e.to_string())?;
    println!("usuário {nome} criado");
    Ok(())
}

fn trocar_pin(nome: &str, resto: &[&str]) -> Result<(), String> {
    let banco = abrir(resto)?;
    let usuario = banco
        .usuario(nome)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("não há usuário {nome}"))?;
    let hash = pin::hash(&ler_pin()?).map_err(|e| e.to_string())?;
    banco
        .trocar_pin(usuario, &hash)
        .map_err(|e| e.to_string())?;
    println!("PIN pessoal de {nome} trocado");
    Ok(())
}

fn listar_dispositivos(resto: &[&str]) -> Result<(), String> {
    for d in abrir(resto)?.dispositivos().map_err(|e| e.to_string())? {
        let estado = if d.revogado {
            "revogado"
        } else if d.erros_seguidos >= ERROS_PARA_BLOQUEAR {
            "bloqueado"
        } else {
            "ativo"
        };
        println!("{}\t{}\t{}\t{estado}", d.id, d.usuario, d.nome);
    }
    Ok(())
}

fn desbloquear(id: &str, resto: &[&str]) -> Result<(), String> {
    let id: IdDoDispositivo = id.parse().map_err(|_| USO.to_string())?;
    if !abrir(resto)?.zerar_erros(id).map_err(|e| e.to_string())? {
        return Err(format!("não há dispositivo {id}"));
    }
    println!("dispositivo {id} desbloqueado");
    Ok(())
}

fn revogar(id: &str, resto: &[&str]) -> Result<(), String> {
    let id: IdDoDispositivo = id.parse().map_err(|_| USO.to_string())?;
    if !abrir(resto)?.revogar(id).map_err(|e| e.to_string())? {
        return Err(format!("não há dispositivo {id}"));
    }
    println!("dispositivo {id} revogado");
    Ok(())
}

fn criar_token(nome: &str, driver: &str, resto: &[&str]) -> Result<(), String> {
    let (opcoes, argumentos) = match resto.iter().position(|a| *a == "--") {
        Some(i) => (&resto[..i], &resto[i + 1..]),
        None => (resto, &[][..]),
    };
    let argumentos: Vec<String> = argumentos.iter().map(|a| a.to_string()).collect();
    abrir(opcoes)?
        .criar_token(nome, driver, &argumentos)
        .map_err(|e| e.to_string())?;
    println!("token {nome} criado; falta configurar");
    Ok(())
}

/// Sobe o driver, pergunta os campos que ele declara e guarda o que o
/// `configurar` deixar. Com o serviço rodando, ele relança o driver do token.
fn configurar_token(nome: &str, resto: &[&str]) -> Result<(), String> {
    let drivers = Path::new(opcao(resto, "--drivers", DRIVERS_PADRAO)?);
    let banco = Arc::new(Mutex::new(abrir(resto)?));
    let registro = travar(&banco)
        .token(nome)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("não há token {nome}"))?;
    let driver =
        Driver::lancar(Command::new(drivers.join(&registro.driver)).args(&registro.argumentos))
            .map_err(|e| e.to_string())?;
    let campos = driver.apresentacao().configuracao.clone();
    let mut token =
        Token::abrir(driver, GuardaNoBanco::novo(banco, registro.id)).map_err(|e| e.to_string())?;
    let mut valores = BTreeMap::new();
    for campo in campos {
        let pergunta = format!("{}: ", campo.rotulo);
        let valor = if campo.secreto && io::stdin().is_terminal() {
            sem_eco(&pergunta)?
        } else {
            if io::stdin().is_terminal() {
                eprint!("{pergunta}");
            }
            ler_linha()?
        };
        valores.insert(campo.nome, sem_quebra(valor));
    }
    token.configurar(valores).map_err(|e| e.to_string())?;
    println!("token {nome} configurado");
    Ok(())
}

fn listar_tokens(resto: &[&str]) -> Result<(), String> {
    let banco = abrir(resto)?;
    for token in banco.tokens().map_err(|e| e.to_string())? {
        let estado = match banco.desatualizado(token.id).map_err(|e| e.to_string())? {
            Some(nomes) => format!("parado ({} recusado)", nomes.join(", ")),
            None if token.geracao == 0 => "não configurado".to_string(),
            None => "ativo".to_string(),
        };
        println!("{}\t{}\t{estado}", token.nome, token.driver);
    }
    Ok(())
}

/// O PIN pessoal novo: num terminal, sem eco e duas vezes; fora dele, a
/// primeira linha do stdin. Nunca por argumento, que fica no histórico e no
/// `ps`.
fn ler_pin() -> Result<Segredo, String> {
    if !io::stdin().is_terminal() {
        return Ok(sem_quebra(ler_linha()?));
    }
    let pin = sem_eco("PIN pessoal: ")?;
    if sem_eco("Repita o PIN: ")?.as_str() != pin.as_str() {
        return Err("os dois PINs não conferem".into());
    }
    Ok(sem_quebra(pin))
}

fn sem_eco(pergunta: &str) -> Result<Zeroizing<String>, String> {
    eprint!("{pergunta}");
    let entrada = io::stdin();
    let normal = termios::tcgetattr(&entrada).map_err(|e| e.to_string())?;
    let mut mudo = normal.clone();
    mudo.local_modes.remove(LocalModes::ECHO);
    termios::tcsetattr(&entrada, OptionalActions::Now, &mudo).map_err(|e| e.to_string())?;
    let linha = ler_linha();
    let _ = termios::tcsetattr(&entrada, OptionalActions::Now, &normal);
    eprintln!();
    linha
}

fn sem_quebra(linha: Zeroizing<String>) -> Segredo {
    Segredo::novo(linha.trim_end_matches(['\n', '\r']).to_string())
}

fn ler_linha() -> Result<Zeroizing<String>, String> {
    let mut linha = Zeroizing::new(String::new());
    io::stdin()
        .lock()
        .read_line(&mut linha)
        .map_err(|e| e.to_string())?;
    Ok(linha)
}
