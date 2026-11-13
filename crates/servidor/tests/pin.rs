//! As regras do PIN pessoal: 3 erros seguidos bloqueiam o dispositivo, o
//! acerto zera o contador, bloqueado nem o PIN certo passa, só o
//! administrador desbloqueia, e tentativas em paralelo não passam do limite.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use protocolo::Segredo;
use servidor::banco::{Banco, ChaveDoBanco, IdDoDispositivo, IdDoUsuario, ler_chave, travar};
use servidor::pin::{self, ERROS_PARA_BLOQUEAR, FalhaDoPin};

const CERTO: &str = "2468";
const ERRADO: &str = "1357";

fn diretorio(nome: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("pin-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Abrir de novo no mesmo diretório é o servidor reiniciando.
fn banco(dir: &Path) -> Mutex<Banco> {
    let arquivo = dir.join("chave");
    if !arquivo.exists() {
        std::fs::write(&arquivo, ChaveDoBanco::aleatorio().unwrap().expor()).unwrap();
    }
    Mutex::new(Banco::abrir(&dir.join("banco.db"), ler_chave(&arquivo).unwrap()).unwrap())
}

fn segredo(pin: &str) -> Segredo {
    Segredo::novo(pin.into())
}

fn usuario(banco: &Mutex<Banco>, nome: &str) -> IdDoUsuario {
    let hash = pin::hash(&segredo(CERTO)).unwrap();
    travar(banco).criar_usuario(nome, &hash).unwrap()
}

fn dispositivo(banco: &Mutex<Banco>, usuario: IdDoUsuario, nome: &str) -> IdDoDispositivo {
    travar(banco)
        .criar_dispositivo(usuario, nome, nome.as_bytes())
        .unwrap()
}

fn tentar(banco: &Mutex<Banco>, dispositivo: IdDoDispositivo, pin: &str) -> Result<(), FalhaDoPin> {
    pin::conferir(banco, dispositivo, &segredo(pin)).map(|_| ())
}

fn erros_seguidos(banco: &Mutex<Banco>, dispositivo: IdDoDispositivo) -> u32 {
    travar(banco)
        .dispositivos()
        .unwrap()
        .into_iter()
        .find(|d| d.id == dispositivo)
        .unwrap()
        .erros_seguidos
}

#[test]
fn tres_erros_seguidos_bloqueiam_e_nem_o_pin_certo_passa() {
    let dir = diretorio("bloqueio");
    let banco = banco(&dir);
    let maria = usuario(&banco, "maria");
    let notebook = dispositivo(&banco, maria, "notebook");

    assert!(matches!(
        tentar(&banco, notebook, ERRADO),
        Err(FalhaDoPin::Errado { restantes: 2 })
    ));
    assert!(matches!(
        tentar(&banco, notebook, ERRADO),
        Err(FalhaDoPin::Errado { restantes: 1 })
    ));
    assert!(matches!(
        tentar(&banco, notebook, ERRADO),
        Err(FalhaDoPin::Bloqueado)
    ));
    assert!(matches!(
        tentar(&banco, notebook, CERTO),
        Err(FalhaDoPin::Bloqueado)
    ));
    assert_eq!(erros_seguidos(&banco, notebook), ERROS_PARA_BLOQUEAR);

    // Nem depois de o servidor reiniciar.
    drop(banco);
    let banco = self::banco(&dir);
    assert!(matches!(
        tentar(&banco, notebook, CERTO),
        Err(FalhaDoPin::Bloqueado)
    ));
}

#[test]
fn o_acerto_zera_o_contador() {
    let dir = diretorio("acerto");
    let banco = banco(&dir);
    let maria = usuario(&banco, "maria");
    let notebook = dispositivo(&banco, maria, "notebook");

    for _ in 1..ERROS_PARA_BLOQUEAR {
        assert!(tentar(&banco, notebook, ERRADO).is_err());
    }
    let autenticado = pin::conferir(&banco, notebook, &segredo(CERTO)).unwrap();
    assert_eq!(autenticado.usuario(), maria);
    assert_eq!(autenticado.dispositivo(), notebook);
    assert_eq!(erros_seguidos(&banco, notebook), 0);

    // Os erros de antes do acerto não contam mais.
    for _ in 1..ERROS_PARA_BLOQUEAR {
        assert!(matches!(
            tentar(&banco, notebook, ERRADO),
            Err(FalhaDoPin::Errado { .. })
        ));
    }
    assert!(tentar(&banco, notebook, CERTO).is_ok());
}

#[test]
fn o_bloqueio_e_do_dispositivo_e_so_o_administrador_desbloqueia() {
    let dir = diretorio("desbloqueio");
    let banco = banco(&dir);
    let maria = usuario(&banco, "maria");
    let notebook = dispositivo(&banco, maria, "notebook");
    let desktop = dispositivo(&banco, maria, "desktop");

    for _ in 0..ERROS_PARA_BLOQUEAR {
        assert!(tentar(&banco, notebook, ERRADO).is_err());
    }
    assert!(matches!(
        tentar(&banco, notebook, CERTO),
        Err(FalhaDoPin::Bloqueado)
    ));
    assert!(
        tentar(&banco, desktop, CERTO).is_ok(),
        "o outro dispositivo da mesma pessoa continua"
    );

    // O que a CLI faz em `dispositivo desbloquear`.
    assert!(travar(&banco).desbloquear(notebook).unwrap());
    assert!(tentar(&banco, notebook, CERTO).is_ok());
}

#[test]
fn dispositivo_desconhecido_nao_e_atendido() {
    let dir = diretorio("desconhecido");
    let banco = banco(&dir);
    let desconhecido: IdDoDispositivo = "999".parse().unwrap();
    assert!(matches!(
        tentar(&banco, desconhecido, CERTO),
        Err(FalhaDoPin::DispositivoDesconhecido)
    ));
    assert!(!travar(&banco).desbloquear(desconhecido).unwrap());
}

/// Cada tentativa conta antes de o Argon2id rodar: uma rajada em paralelo
/// não ganha mais chutes do que o limite.
#[test]
fn tentativas_em_paralelo_nao_passam_do_limite() {
    const RAJADA: usize = 12;
    let dir = diretorio("paralelo");
    let banco = Arc::new(banco(&dir));
    let maria = usuario(&banco, "maria");
    let notebook = dispositivo(&banco, maria, "notebook");

    let largada = Arc::new(Barrier::new(RAJADA));
    let chutes: Vec<_> = (0..RAJADA)
        .map(|i| {
            let banco = banco.clone();
            let largada = largada.clone();
            thread::spawn(move || {
                largada.wait();
                tentar(&banco, notebook, &format!("{i:04}x"))
            })
        })
        .collect();
    let resultados: Vec<_> = chutes.into_iter().map(|c| c.join().unwrap()).collect();

    let conferidos = resultados
        .iter()
        .filter(|r| matches!(r, Err(FalhaDoPin::Errado { .. })))
        .count();
    // O último chute contado também foi conferido, e voltou como bloqueio.
    assert_eq!(conferidos, ERROS_PARA_BLOQUEAR as usize - 1);
    assert!(
        resultados
            .iter()
            .all(|r| matches!(r, Err(FalhaDoPin::Errado { .. } | FalhaDoPin::Bloqueado)))
    );
    assert_eq!(erros_seguidos(&banco, notebook), ERROS_PARA_BLOQUEAR);
}

#[test]
fn trocar_o_pin_vale_na_proxima_tentativa() {
    let dir = diretorio("trocar");
    let banco = banco(&dir);
    let maria = usuario(&banco, "maria");
    let notebook = dispositivo(&banco, maria, "notebook");

    let novo = pin::hash(&segredo("8642")).unwrap();
    travar(&banco).trocar_pin(maria, &novo).unwrap();
    assert!(tentar(&banco, notebook, CERTO).is_err());
    assert!(tentar(&banco, notebook, "8642").is_ok());
    assert_eq!(travar(&banco).usuario("maria").unwrap(), Some(maria));
}
