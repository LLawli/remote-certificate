//! O lançador dos drivers: `remote-certificate isolar -- <driver> [argumentos]`.
//!
//! Restringe o próprio processo e então vira o driver (`execve`); as
//! restrições atravessam o `execve` e valem para os filhos do driver. Não pede
//! privilégio nenhum: funciona num container com `cap_drop: ALL`.
//!
//! - **Landlock**: o driver lê e executa o sistema (`/usr`, `/lib`, `/etc`) e
//!   a pasta do próprio executável, e escreve só no diretório de trabalho, que
//!   o servidor faz ser o diretório de estado do token. Só conecta nas portas
//!   TCP do manifesto, não escuta em porta nenhuma, só conecta nos sockets
//!   UNIX do manifesto (o do `pcscd`, para um token físico) e não manda sinal
//!   para fora dele.
//! - **Limites**: sem core dump, com teto de memória e de arquivos abertos.
//!
//! O que o driver precisa vem do manifesto ao lado do executável
//! (`<driver>.manifesto.json`), que a imagem do driver instala. Sem manifesto,
//! o driver não tem rede.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, NetPort, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, path_beneath_rules,
};
use rustix::process::{Resource, Rlimit};
use serde::Deserialize;

/// A ABI do Landlock pedida. Num kernel mais velho, vale o que ele tiver
/// (`docs/seguranca.md`); o nível obtido vai para o log.
const ABI_PEDIDA: ABI = ABI::V9;

/// O sistema, que o driver lê e executa: as bibliotecas e o carregador da
/// glibc, a configuração de DNS e os certificados das autoridades.
const SISTEMA: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// O nome da máquina e a versão do kernel, o mesmo que o `uname` diz. O
/// RemoteID registra a instalação com o nome da máquina e é recusado sem ele.
const DO_KERNEL: &[&str] = &["/proc/sys/kernel/hostname", "/proc/sys/kernel/osrelease"];

/// Dispositivos que todo programa abre (`/dev/null` para descartar uma saída).
const DISPOSITIVOS: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];

/// Arquivos abertos ao mesmo tempo.
const ARQUIVOS_ABERTOS: u64 = 256;

/// Teto de memória virtual de cada processo do driver, quando o manifesto não
/// diz outro.
const MEMORIA_PADRAO_MIB: u64 = 1024;

/// O que o driver precisa além do sistema, declarado por ele.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifesto {
    /// As portas TCP em que o driver conecta (o RemoteID, na 443).
    #[serde(default)]
    pub tcp: Vec<u16>,
    /// Os sockets UNIX em que o driver conecta, por caminho absoluto (o do
    /// `pcscd`, para falar com um leitor de smartcard). Cada um é um socket,
    /// nunca uma pasta.
    #[serde(default)]
    pub unix: Vec<PathBuf>,
    /// Teto de memória virtual de cada processo, em MiB.
    #[serde(default)]
    pub memoria_mib: Option<u64>,
}

impl Manifesto {
    /// O arquivo do manifesto de um driver: o executável com
    /// `.manifesto.json` no fim do nome.
    pub fn caminho(driver: &Path) -> PathBuf {
        let mut nome = driver.as_os_str().to_owned();
        nome.push(".manifesto.json");
        PathBuf::from(nome)
    }

    /// O manifesto do driver; sem arquivo, o padrão (sem rede).
    pub fn ler(driver: &Path) -> io::Result<Manifesto> {
        let manifesto: Manifesto = match std::fs::read(Manifesto::caminho(driver)) {
            Ok(conteudo) => serde_json::from_slice(&conteudo).map_err(io::Error::other)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Manifesto::default()),
            Err(e) => return Err(e),
        };
        manifesto.conferir()?;
        Ok(manifesto)
    }

    /// Um socket do manifesto é um caminho absoluto e não é uma pasta: numa
    /// pasta, a regra valeria para todo socket dentro dela. Um socket que não
    /// existe (o `pcscd` fora do ar) não impede o driver de subir.
    fn conferir(&self) -> io::Result<()> {
        for socket in &self.unix {
            if !socket.is_absolute() {
                return Err(io::Error::other(format!(
                    "manifesto: o socket {} não é um caminho absoluto",
                    socket.display()
                )));
            }
            if socket.is_dir() {
                return Err(io::Error::other(format!(
                    "manifesto: {} é uma pasta, não um socket",
                    socket.display()
                )));
            }
        }
        Ok(())
    }
}

/// Quanto do Landlock o kernel aplicou.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nivel {
    /// Tudo o que foi pedido.
    Completo,
    /// Uma parte: um kernel com uma ABI anterior à pedida.
    Parcial(Option<i32>),
    /// Nada: o kernel não tem o Landlock ou ele está desligado.
    Nenhum,
}

impl fmt::Display for Nivel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nivel::Completo => write!(f, "Landlock completo (ABI {})", ABI_PEDIDA as i32),
            Nivel::Parcial(Some(abi)) => write!(f, "Landlock parcial (o kernel tem a ABI {abi})"),
            Nivel::Parcial(None) => f.write_str("Landlock parcial"),
            Nivel::Nenhum => f.write_str("sem Landlock (o kernel não tem ou está desligado)"),
        }
    }
}

/// Restringe este processo: Landlock com o que o manifesto declara, e os
/// limites. `pasta_do_driver` fica legível; `estado`, gravável.
pub fn restringir(
    pasta_do_driver: &Path,
    estado: &Path,
    manifesto: &Manifesto,
) -> io::Result<Nivel> {
    limitar(manifesto)?;
    let leitura = AccessFs::from_read(ABI_PEDIDA);
    // No estado, tudo menos executar: o driver não roda o que ele mesmo grava.
    let tudo = AccessFs::from_all(ABI_PEDIDA);
    let mut regras = Ruleset::default()
        .handle_access(tudo)
        .and_then(|r| r.handle_access(AccessNet::from_all(ABI_PEDIDA)))
        .and_then(|r| r.scope(Scope::from_all(ABI_PEDIDA)))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(SISTEMA, leitura)))
        .and_then(|r| r.add_rules(path_beneath_rules(DO_KERNEL, AccessFs::ReadFile)))
        .and_then(|r| r.add_rules(path_beneath_rules([pasta_do_driver], leitura)))
        .and_then(|r| {
            r.add_rules(path_beneath_rules(
                DISPOSITIVOS,
                AccessFs::ReadFile | AccessFs::WriteFile,
            ))
        })
        .and_then(|r| r.add_rules(path_beneath_rules([estado], tudo & !AccessFs::Execute)))
        .and_then(|r| r.add_rules(path_beneath_rules(&manifesto.unix, AccessFs::ResolveUnix)))
        .map_err(io::Error::other)?;
    for porta in &manifesto.tcp {
        regras = regras
            .add_rule(NetPort::new(*porta, AccessNet::ConnectTcp))
            .map_err(io::Error::other)?;
    }
    let status = regras.restrict_self().map_err(io::Error::other)?;
    Ok(match (status.ruleset, status.landlock) {
        (RulesetStatus::FullyEnforced, _) => Nivel::Completo,
        (RulesetStatus::PartiallyEnforced, LandlockStatus::Available { effective_abi, .. }) => {
            Nivel::Parcial(Some(effective_abi as i32))
        }
        (RulesetStatus::PartiallyEnforced, _) => Nivel::Parcial(None),
        (RulesetStatus::NotEnforced, _) => Nivel::Nenhum,
    })
}

fn limitar(manifesto: &Manifesto) -> io::Result<()> {
    let memoria = manifesto.memoria_mib.unwrap_or(MEMORIA_PADRAO_MIB) * 1024 * 1024;
    baixar(Resource::Core, 0)?;
    baixar(Resource::As, memoria)?;
    baixar(Resource::Nofile, ARQUIVOS_ABERTOS)?;
    Ok(())
}

/// Põe o limite em `valor`, ou no teto que o ambiente já impôs, se for menor:
/// sem privilégio, subir um teto falha, e o driver não subiria.
fn baixar(recurso: Resource, valor: u64) -> io::Result<()> {
    let maximo = rustix::process::getrlimit(recurso).maximum;
    let valor = maximo.map_or(valor, |maximo| maximo.min(valor));
    rustix::process::setrlimit(
        recurso,
        Rlimit {
            current: Some(valor),
            maximum: Some(valor),
        },
    )?;
    Ok(())
}

/// `isolar -- <driver> [argumentos]`: restringe e vira o driver. Só volta se
/// algo deu errado.
pub fn executar(args: &[OsString]) -> io::Error {
    let (driver, argumentos) = match args {
        [separador, driver, argumentos @ ..] if separador == OsStr::new("--") => {
            (Path::new(driver), argumentos)
        }
        _ => return io::Error::other("uso: remote-certificate isolar -- <driver> [argumentos]"),
    };
    let preparado = (|| {
        // O caminho do driver resolvido, para a regra valer para a pasta de
        // verdade e não para um link.
        let driver = driver.canonicalize()?;
        let pasta = driver
            .parent()
            .ok_or_else(|| io::Error::other("o driver não está numa pasta"))?
            .to_owned();
        let manifesto = Manifesto::ler(&driver)?;
        let estado = std::env::current_dir()?;
        // Na raiz, a regra liberaria o disco inteiro, o banco junto.
        if pasta == Path::new("/") || estado == Path::new("/") {
            return Err(io::Error::other(
                "nem o driver nem o diretório de trabalho podem estar na raiz",
            ));
        }
        let nivel = restringir(&pasta, &estado, &manifesto)?;
        let nome = driver.file_name().unwrap_or_default().to_string_lossy();
        eprintln!(
            "isolar: {nome}: {nivel}; TCP {:?}; UNIX {:?}",
            manifesto.tcp, manifesto.unix
        );
        Ok::<_, io::Error>(driver)
    })();
    match preparado {
        Ok(driver) => Command::new(driver).args(argumentos).exec(),
        Err(e) => io::Error::new(e.kind(), format!("isolar {}: {e}", driver.display())),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_manifesto_fica_ao_lado_do_executavel() {
        assert_eq!(
            Manifesto::caminho(Path::new("/drivers/remote-certificate-driver-remoteid")),
            Path::new("/drivers/remote-certificate-driver-remoteid.manifesto.json")
        );
    }

    #[test]
    fn sem_manifesto_o_driver_fica_sem_rede() {
        let manifesto = Manifesto::ler(Path::new("/nao/existe/driver")).unwrap();
        assert_eq!(manifesto, Manifesto::default());
        assert!(manifesto.tcp.is_empty());
    }

    #[test]
    fn socket_do_manifesto_e_um_caminho_absoluto_e_nao_uma_pasta() {
        let ler = |json: &str| serde_json::from_str::<Manifesto>(json).unwrap().conferir();
        assert!(ler(r#"{"unix": ["/run/pcscd/pcscd.comm"]}"#).is_ok());
        assert!(ler(r#"{"unix": ["/nao/existe.sock"]}"#).is_ok());
        assert!(ler(r#"{"unix": ["run/pcscd/pcscd.comm"]}"#).is_err());
        assert!(ler(r#"{"unix": ["/run"]}"#).is_err());
        assert!(ler(r#"{"unix": ["/"]}"#).is_err());
    }

    #[test]
    fn campo_desconhecido_no_manifesto_e_recusado() {
        let lido: Result<Manifesto, _> = serde_json::from_str(r#"{"tcp": [443], "udp": [53]}"#);
        assert!(lido.is_err());
    }
}
