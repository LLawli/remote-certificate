//! O `remoteid servir` como processo filho: JSON por linha no stdin e stdout.

use std::io::{self, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;

pub struct Servir {
    filho: Child,
    entrada: Option<ChildStdin>,
    saida: BufReader<ChildStdout>,
}

impl Servir {
    /// `estado` é o diretório do RemoteID deste token; `servidor` troca a
    /// Certisign por outro endereço (o servidor falso, nos testes).
    pub fn subir(remoteid: &Path, estado: &Path, servidor: Option<&str>) -> io::Result<Servir> {
        let mut comando = Command::new(remoteid);
        comando
            .arg("servir")
            .env("REMOTEID_HOME", estado)
            // Num container não há chaveiro: a senha fica cifrada pelo PIN
            // local, que o servidor guarda.
            .env("REMOTEID_COFRE", "nenhum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if let Some(url) = servidor {
            comando.env("REMOTEID_SERVIDOR", url);
        }
        let mut filho = comando.spawn()?;
        Ok(Servir {
            entrada: filho.stdin.take(),
            saida: BufReader::new(filho.stdout.take().expect("stdout com pipe")),
            filho,
        })
    }

    pub fn enviar(&mut self, mensagem: &Value) -> io::Result<()> {
        let entrada = self
            .entrada
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        writeln!(entrada, "{mensagem}")?;
        entrada.flush()
    }

    pub fn receber(&mut self) -> io::Result<Value> {
        let mut linha = String::new();
        if protocolo::ler_linha(&mut self.saida, &mut linha)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "o remoteid servir parou",
            ));
        }
        serde_json::from_str(&linha).map_err(io::Error::other)
    }
}

impl Drop for Servir {
    fn drop(&mut self) {
        // Sem stdin, o `servir` termina sozinho.
        drop(self.entrada.take());
        let _ = self.filho.wait();
    }
}
