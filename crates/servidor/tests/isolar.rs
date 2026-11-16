//! O lançador dos drivers isolando um driver de verdade: um script que tenta
//! o que um driver comprometido tentaria (ler o banco, escrever fora do
//! estado, rodar o que gravou, conectar e mandar sinal para fora) e diz o que
//! conseguiu.
//!
//! Num kernel sem Landlock, o lançador diz "sem Landlock" e os testes do
//! Landlock não têm o que conferir; os limites de processo valem do mesmo jeito.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};

use servidor::banco::{Banco, ChaveDoBanco};
use servidor::lancador::Lancador;

const LANCADOR: &str = env!("CARGO_BIN_EXE_remote-certificate");

struct Isolado {
    dir: PathBuf,
}

impl Isolado {
    /// Um diretório com o driver (`drivers/driver`, o script), o estado dele
    /// e, ao lado, um "banco" que o driver não deve alcançar.
    fn novo(nome: &str, script: &str, manifesto: Option<&str>) -> Isolado {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("isolar-{nome}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("drivers")).unwrap();
        std::fs::create_dir_all(dir.join("estado")).unwrap();
        std::fs::write(dir.join("banco.db"), "o banco").unwrap();
        let driver = dir.join("drivers/driver");
        std::fs::write(&driver, format!("#!/bin/bash\n{script}\n")).unwrap();
        std::fs::set_permissions(&driver, std::fs::Permissions::from_mode(0o755)).unwrap();
        if let Some(manifesto) = manifesto {
            std::fs::write(dir.join("drivers/driver.manifesto.json"), manifesto).unwrap();
        }
        Isolado { dir }
    }

    fn rodar(&self) -> Output {
        Command::new(LANCADOR)
            .args(["isolar", "--"])
            .arg(self.dir.join("drivers/driver"))
            .current_dir(self.dir.join("estado"))
            .output()
            .unwrap()
    }
}

/// O stdout do driver isolado, ou `None` quando o kernel não tem a ABI do
/// Landlock que o teste confere (a 4 para a rede, a 6 para os sinais). O
/// lançador pede a 9 e aplica o que o kernel tiver.
fn com_landlock(saida: &Output, abi_minima: u32) -> Option<String> {
    let log = String::from_utf8_lossy(&saida.stderr);
    // Com `--nocapture` (o `scripts/ci.sh` roda assim), o nível vai para o log.
    eprintln!("{}", log.lines().next().unwrap_or_default());
    if log.contains("sem Landlock") {
        eprintln!("kernel sem Landlock: nada a conferir ({log})");
        return None;
    }
    let abi: u32 = log
        .split("ABI ")
        .nth(1)
        .and_then(|resto| resto.split(')').next())
        .and_then(|numero| numero.parse().ok())
        .unwrap_or_else(|| panic!("nível sem a ABI: {log}"));
    if abi < abi_minima {
        eprintln!("o kernel tem a ABI {abi} do Landlock; o teste pede a {abi_minima}");
        return None;
    }
    Some(String::from_utf8_lossy(&saida.stdout).into_owned())
}

/// `rotulo:sim` se o comando deu certo, `rotulo:nao` se não.
fn tenta(rotulo: &str, comando: &str) -> String {
    format!("( {comando} ) >/dev/null 2>&1 && echo {rotulo}:sim || echo {rotulo}:nao\n")
}

#[test]
fn o_driver_le_o_sistema_e_escreve_so_no_estado() {
    let script = [
        tenta("sistema", "cat /etc/passwd"),
        tenta("estado", "echo x > gravado && cat gravado"),
        tenta("banco", "cat ../banco.db"),
        tenta("fora", "echo x > ../fora"),
        tenta("ao_lado_do_driver", "echo x > ../drivers/outro"),
    ]
    .concat();
    let isolado = Isolado::novo("arquivos", &script, None);
    let saida = isolado.rodar();
    assert!(saida.status.success(), "{saida:?}");
    let Some(stdout) = com_landlock(&saida, 1) else {
        return;
    };
    assert_eq!(
        stdout,
        "sistema:sim\nestado:sim\nbanco:nao\nfora:nao\nao_lado_do_driver:nao\n"
    );
    assert!(!isolado.dir.join("fora").exists());
}

#[test]
fn o_driver_nao_roda_o_que_gravou() {
    let script = [
        tenta("copia", "cp /bin/true ./copia"),
        tenta("roda", "./copia"),
    ]
    .concat();
    let saida = Isolado::novo("executar", &script, None).rodar();
    let Some(stdout) = com_landlock(&saida, 1) else {
        return;
    };
    assert_eq!(stdout, "copia:sim\nroda:nao\n");
}

#[test]
fn o_driver_so_conecta_nas_portas_do_manifesto() {
    let declarada = TcpListener::bind("127.0.0.1:0").unwrap();
    let outra = TcpListener::bind("127.0.0.1:0").unwrap();
    let porta = |l: &TcpListener| l.local_addr().unwrap().port();
    let script = [
        tenta(
            "declarada",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{}", porta(&declarada)),
        ),
        tenta(
            "outra",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{}", porta(&outra)),
        ),
    ]
    .concat();
    let manifesto = format!(r#"{{"tcp": [{}]}}"#, porta(&declarada));

    let saida = Isolado::novo("rede", &script, Some(&manifesto)).rodar();
    let Some(stdout) = com_landlock(&saida, 4) else {
        return;
    };
    assert_eq!(stdout, "declarada:sim\noutra:nao\n");

    // Sem manifesto, nenhuma porta.
    let saida = Isolado::novo("sem-rede", &script, None).rodar();
    assert_eq!(
        com_landlock(&saida, 4).unwrap(),
        "declarada:nao\noutra:nao\n"
    );
}

#[test]
fn o_driver_so_conecta_nos_sockets_unix_do_manifesto() {
    // Os sockets ficam fora do estado (lá o driver pode tudo), como o do
    // `pcscd`. Antes da ABI 9 o Landlock não filtra socket UNIX.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("isolar-unix-sockets");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let declarado = dir.join("declarado.sock");
    let outro = dir.join("outro.sock");
    let _ouvindo = [&declarado, &outro].map(|s| UnixListener::bind(s).unwrap());
    let conectar = |s: &PathBuf| {
        format!(
            "python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])' {}",
            s.display()
        )
    };
    let script = [
        tenta("declarado", &conectar(&declarado)),
        tenta("outro", &conectar(&outro)),
    ]
    .concat();
    let manifesto = format!(r#"{{"unix": ["{}"]}}"#, declarado.display());

    let saida = Isolado::novo("unix", &script, Some(&manifesto)).rodar();
    let Some(stdout) = com_landlock(&saida, 9) else {
        return;
    };
    assert_eq!(stdout, "declarado:sim\noutro:nao\n");

    // Sem manifesto, nenhum.
    let saida = Isolado::novo("sem-unix", &script, None).rodar();
    assert_eq!(
        com_landlock(&saida, 9).unwrap(),
        "declarado:nao\noutro:nao\n"
    );
}

#[test]
fn manifesto_com_uma_pasta_de_sockets_nao_deixa_o_driver_subir() {
    let isolado = Isolado::novo("unix-pasta", "echo subiu", Some(r#"{"unix": ["/run"]}"#));
    let saida = isolado.rodar();
    assert!(!saida.status.success(), "{saida:?}");
    assert!(saida.stdout.is_empty());
}

#[test]
fn o_driver_nao_manda_sinal_para_fora() {
    // O pai do driver é este teste.
    let script = [
        tenta("a_si", "kill -0 $$"),
        tenta("ao_pai", "kill -0 $PPID"),
    ]
    .concat();
    let saida = Isolado::novo("sinal", &script, None).rodar();
    let Some(stdout) = com_landlock(&saida, 6) else {
        return;
    };
    assert_eq!(stdout, "a_si:sim\nao_pai:nao\n");
}

#[test]
fn o_driver_roda_sem_core_e_com_tetos() {
    let script = "echo $(ulimit -c) $(ulimit -v) $(ulimit -n)";
    let saida = Isolado::novo("limites", script, None).rodar();
    assert!(saida.status.success(), "{saida:?}");
    // O padrão é 1 GiB (em KiB no `ulimit -v`).
    assert_eq!(String::from_utf8_lossy(&saida.stdout), "0 1048576 256\n");

    let saida = Isolado::novo(
        "limites-do-manifesto",
        script,
        Some(r#"{"memoria_mib": 512}"#),
    )
    .rodar();
    assert_eq!(String::from_utf8_lossy(&saida.stdout), "0 524288 256\n");
}

/// Um teto que o ambiente já impôs, menor que o do lançador, fica como está:
/// o lançador só baixa os limites, e o driver sobe do mesmo jeito.
#[test]
fn com_tetos_menores_o_driver_sobe_com_eles() {
    let isolado = Isolado::novo(
        "tetos-menores",
        "echo $(ulimit -c) $(ulimit -v) $(ulimit -n)",
        None,
    );
    let driver = isolado.dir.join("drivers/driver");
    let saida = Command::new("bash")
        .arg("-c")
        .arg(r#"ulimit -n 128 -v 600000 && exec "$0" isolar -- "$1""#)
        .arg(LANCADOR)
        .arg(&driver)
        .current_dir(isolado.dir.join("estado"))
        .output()
        .unwrap();
    assert!(saida.status.success(), "{saida:?}");
    assert_eq!(String::from_utf8_lossy(&saida.stdout), "0 600000 128\n");
}

#[test]
fn manifesto_ilegivel_nao_deixa_o_driver_subir() {
    let saida = Isolado::novo("manifesto-ruim", "echo subiu", Some(r#"{"udp": [53]}"#)).rodar();
    assert!(!saida.status.success());
    assert!(saida.stdout.is_empty(), "o driver subiu: {saida:?}");
    assert!(String::from_utf8_lossy(&saida.stderr).contains("unknown field"));
}

#[test]
fn na_raiz_o_lancador_recusa() {
    let isolado = Isolado::novo("raiz", "echo subiu", None);
    let saida = Command::new(LANCADOR)
        .args(["isolar", "--"])
        .arg(isolado.dir.join("drivers/driver"))
        .current_dir("/")
        .output()
        .unwrap();
    assert!(!saida.status.success());
    assert!(saida.stdout.is_empty(), "o driver subiu: {saida:?}");
}

#[test]
fn sem_o_separador_o_lancador_recusa() {
    let saida = Command::new(LANCADOR)
        .args(["isolar", "/bin/true"])
        .output()
        .unwrap();
    assert!(!saida.status.success());
}

/// O servidor sobe o driver de cada token pelo lançador, num diretório de
/// estado só daquele token (`0700`), que é o diretório de trabalho.
#[test]
fn cada_token_tem_o_seu_estado() {
    let isolado = Isolado::novo("lancador", "pwd; echo x > gravado", None);
    let dir = &isolado.dir;
    std::fs::write(
        dir.join("chave"),
        ChaveDoBanco::aleatorio().unwrap().expor(),
    )
    .unwrap();
    let banco = Banco::abrir(
        &dir.join("banco.db.sqlite"),
        servidor::banco::ler_chave(&dir.join("chave")).unwrap(),
    )
    .unwrap();
    banco.criar_token("um", "driver", &[]).unwrap();
    banco.criar_token("outro", "driver", &[]).unwrap();
    let lancador = Lancador::novo(dir.join("drivers"), dir.join("estados")).isolado(LANCADOR);

    let mut estados = Vec::new();
    for registro in banco.tokens().unwrap() {
        let saida = lancador.comando(&registro).unwrap().output().unwrap();
        assert!(saida.status.success(), "{saida:?}");
        let estado = lancador.estado(&registro);
        assert_eq!(
            String::from_utf8_lossy(&saida.stdout).trim(),
            estado.canonicalize().unwrap().display().to_string()
        );
        assert!(estado.join("gravado").exists());
        let modo = std::fs::metadata(&estado).unwrap().permissions().mode();
        assert_eq!(modo & 0o777, 0o700);
        estados.push(estado);
    }
    assert_eq!(estados.len(), 2);
    assert_ne!(estados[0], estados[1]);
}
