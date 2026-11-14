//! A conversa entre a face (o módulo PKCS#11, dentro do navegador ou do
//! assinador) e o agente da estação: JSON, uma mensagem por linha, numa
//! conexão local. No Linux, um socket Unix em
//! `$XDG_RUNTIME_DIR/remote-certificate/agente.sock`.
//!
//! Uma conexão é uma aplicação: o PIN pessoal que ela manda no `entrar` vale
//! só para ela, como o `C_Login` do PKCS#11. A face pergunta e espera a
//! resposta; quando o token pede o OTP, é o agente quem pergunta à pessoa,
//! numa janela, e a face só recebe o fim.

pub mod janela;

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;

use protocolo::{Chave, Mecanismo, Segredo};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A maior mensagem, nos dois sentidos: um documento de até 4 MiB em base64.
pub const LIMITE: usize = 6 * 1024 * 1024;
/// Troca o caminho do socket do agente.
pub const ENV_SOCKET: &str = "REMOTE_CERTIFICATE_AGENTE";
/// O diretório do socket dentro de `$XDG_RUNTIME_DIR`.
pub const DIRETORIO: &str = "remote-certificate";
pub const SOCKET: &str = "agente.sock";

/// O que a face pede.
#[derive(Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaFace {
    // Com chaves, mesmo vazias: uma variante sem campos aceitaria campos
    // desconhecidos apesar do `deny_unknown_fields`.
    Listar {},
    /// O PIN pessoal, do `C_Login`.
    Entrar {
        pin: Segredo,
    },
    Sair {},
    Assinar {
        token: String,
        chave: String,
        mecanismo: Mecanismo,
        #[serde(with = "protocolo::b64")]
        dados: Vec<u8>,
    },
}

/// Sem o PIN e sem os dados.
impl fmt::Debug for DaFace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaFace::Listar {} => f.write_str("Listar"),
            DaFace::Entrar { .. } => f.write_str("Entrar"),
            DaFace::Sair {} => f.write_str("Sair"),
            DaFace::Assinar {
                token,
                chave,
                mecanismo,
                dados,
            } => f
                .debug_struct("Assinar")
                .field("token", token)
                .field("chave", chave)
                .field("mecanismo", mecanismo)
                .field("dados", &dados.len())
                .finish(),
        }
    }
}

/// O que o agente responde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case", deny_unknown_fields)]
pub enum DoAgente {
    Chaves {
        chaves: Vec<ChaveDoToken>,
    },
    Entrou {},
    Saiu {},
    Assinatura {
        #[serde(with = "protocolo::b64")]
        assinatura: Vec<u8>,
    },
    Falha {
        erro: Falha,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaveDoToken {
    /// O token no servidor: vai no `assinar`.
    pub token: String,
    #[serde(flatten)]
    pub chave: Chave,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Falha {
    pub tipo: TipoDeFalha,
    /// Para a pessoa ler.
    pub mensagem: String,
    /// Com `pin_errado`: quantas tentativas faltam até bloquear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restantes: Option<u32>,
}

impl Falha {
    pub fn nova(tipo: TipoDeFalha, mensagem: impl Into<String>) -> Falha {
        Falha {
            tipo,
            mensagem: mensagem.into(),
            restantes: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoDeFalha {
    PinErrado,
    /// O dispositivo está bloqueado até o administrador desbloquear.
    Bloqueado,
    /// Falta o `entrar`, ou a sessão venceu ou caiu com a conexão.
    NaoAutenticado,
    TokenDesconhecido,
    /// O token recusou um fator guardado e espera o administrador.
    TokenParado,
    ChaveAusente,
    MecanismoNaoSuportado,
    /// A pessoa fechou a janela do OTP, ou não respondeu a tempo.
    Cancelado,
    /// Este computador não foi pareado com um servidor.
    NaoPareado,
    /// O servidor não responde, ou não atende mais este dispositivo.
    SemServidor,
    PedidoInvalido,
    /// O token ou o driver falhou.
    Token,
    Interno,
    #[serde(other)]
    Outro,
}

/// Escreve `mensagem` numa linha.
pub fn escrever(escritor: &mut impl Write, mensagem: &impl Serialize) -> io::Result<()> {
    let mut linha = serde_json::to_vec(mensagem).map_err(io::Error::other)?;
    linha.push(b'\n');
    escritor.write_all(&linha)?;
    escritor.flush()
}

/// Lê a próxima mensagem; `None` quando o outro lado fechou. Uma linha maior
/// que [`LIMITE`] é erro, sem ser lida inteira.
pub fn ler<T: DeserializeOwned>(leitor: &mut impl BufRead) -> io::Result<Option<T>> {
    let mut linha = Vec::new();
    let lidos = leitor
        .by_ref()
        .take(LIMITE as u64 + 1)
        .read_until(b'\n', &mut linha)?;
    if lidos == 0 {
        return Ok(None);
    }
    if lidos > LIMITE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mensagem maior que o limite",
        ));
    }
    serde_json::from_slice(&linha)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Onde o agente atende: [`ENV_SOCKET`], ou o socket em `$XDG_RUNTIME_DIR`.
pub fn caminho_do_socket() -> Option<PathBuf> {
    if let Some(caminho) = std::env::var_os(ENV_SOCKET) {
        return Some(PathBuf::from(caminho));
    }
    let execucao = std::env::var_os("XDG_RUNTIME_DIR")?;
    Some(PathBuf::from(execucao).join(DIRETORIO).join(SOCKET))
}

/// A face conectada ao agente.
#[cfg(unix)]
pub struct Cliente {
    leitor: io::BufReader<std::os::unix::net::UnixStream>,
    escritor: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl Cliente {
    pub fn conectar() -> io::Result<Cliente> {
        let caminho = caminho_do_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "sem XDG_RUNTIME_DIR nem socket")
        })?;
        Cliente::conectar_em(&caminho)
    }

    pub fn conectar_em(caminho: &std::path::Path) -> io::Result<Cliente> {
        let escritor = std::os::unix::net::UnixStream::connect(caminho)?;
        Ok(Cliente {
            leitor: io::BufReader::new(escritor.try_clone()?),
            escritor,
        })
    }

    /// Manda o pedido e espera a resposta: com o OTP, o tempo que a pessoa
    /// levar.
    pub fn pedir(&mut self, pedido: &DaFace) -> io::Result<DoAgente> {
        escrever(&mut self.escritor, pedido)?;
        ler(&mut self.leitor)?.ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn debug_nao_mostra_o_pin_nem_os_dados() {
        let entrar = DaFace::Entrar {
            pin: Segredo::novo("2468".into()),
        };
        assert!(!format!("{entrar:?}").contains("2468"));
        let assinar = DaFace::Assinar {
            token: "RemoteID".into(),
            chave: "k1".into(),
            mecanismo: Mecanismo::Sha256RsaPkcs,
            dados: b"procuracao".to_vec(),
        };
        let debug = format!("{assinar:?}");
        assert!(
            !debug.contains("procuracao") && !debug.contains("112"),
            "{debug}"
        );
    }

    #[test]
    fn as_mensagens_tem_o_formato_do_protocolo() {
        let mut linha = Vec::new();
        escrever(
            &mut linha,
            &DaFace::Assinar {
                token: "RemoteID".into(),
                chave: "k1".into(),
                mecanismo: Mecanismo::Sha256RsaPkcs,
                dados: vec![0, 1, 2],
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(linha).unwrap(),
            "{\"tipo\":\"assinar\",\"token\":\"RemoteID\",\"chave\":\"k1\",\
             \"mecanismo\":\"CKM_SHA256_RSA_PKCS\",\"dados\":\"AAEC\"}\n"
        );
        let falha: DoAgente = ler(&mut &br#"{"tipo":"falha","erro":{"tipo":"pin_errado","mensagem":"PIN errado","restantes":2}}
"#[..])
            .unwrap()
            .unwrap();
        assert_eq!(
            falha,
            DoAgente::Falha {
                erro: Falha {
                    tipo: TipoDeFalha::PinErrado,
                    mensagem: "PIN errado".into(),
                    restantes: Some(2),
                }
            }
        );
        assert!(
            ler::<DaFace>(&mut &b"{\"tipo\":\"listar\",\"extra\":1}\n"[..]).is_err(),
            "campo desconhecido é recusado"
        );
        assert!(
            ler::<DaFace>(&mut &b""[..]).unwrap().is_none(),
            "fim é None"
        );
    }

    #[test]
    fn mensagem_maior_que_o_limite_e_recusada_sem_ler_inteira() {
        let grande = vec![b'a'; LIMITE * 2];
        let mut leitor = &grande[..];
        let falha = ler::<DaFace>(&mut leitor).unwrap_err();
        assert_eq!(falha.kind(), io::ErrorKind::InvalidData);
        assert!(leitor.len() >= LIMITE - 1, "não leu tudo");
    }
}
