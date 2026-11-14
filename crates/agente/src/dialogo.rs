//! A pergunta à pessoa quando o token pede um fator dela (o OTP).
//!
//! O agente não desenha janela: chama um programa à parte, que vive o tempo
//! da pergunta. O pedido vai pelo stdin e os valores voltam pelo stdout, nunca
//! por argumento nem por ambiente, que outros processos leem em `/proc`. Cada
//! sistema operacional tem o seu programa; os testes usam um que responde
//! sozinho.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use protocolo::Segredo;

/// Troca o programa da janela.
pub const ENV_DIALOGO: &str = "REMOTE_CERTIFICATE_DIALOGO";
/// O programa da janela, instalado ao lado do agente.
pub const PROGRAMA: &str = "remote-certificate-dialogo";
/// O que o servidor espera a pessoa responder antes de cancelar
/// (`servidor::agente::PRAZO_DA_PESSOA`).
pub const PRAZO: Duration = Duration::from_secs(3 * 60);
/// A maior resposta que a janela pode dar.
const RESPOSTA_MAXIMA: u64 = 64 * 1024;

pub use ipc::janela::{FatorPedido, Pergunta, Valores};

pub trait Dialogo: Send + Sync {
    /// `None` é desistir: a pessoa fechou a janela, ou não respondeu a tempo.
    fn perguntar(&self, pergunta: &Pergunta) -> Option<BTreeMap<String, Segredo>>;
}

/// A janela como um programa à parte.
pub struct DialogoExterno {
    programa: PathBuf,
    prazo: Duration,
}

impl DialogoExterno {
    pub fn novo(programa: impl Into<PathBuf>, prazo: Duration) -> DialogoExterno {
        DialogoExterno {
            programa: programa.into(),
            prazo,
        }
    }

    /// [`ENV_DIALOGO`], ou [`PROGRAMA`] ao lado do executável do agente.
    pub fn padrao() -> DialogoExterno {
        let programa = std::env::var_os(ENV_DIALOGO)
            .map(PathBuf::from)
            .or_else(|| {
                std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|dir| dir.join(PROGRAMA)))
            })
            .unwrap_or_else(|| PathBuf::from(PROGRAMA));
        DialogoExterno::novo(programa, PRAZO)
    }
}

impl Dialogo for DialogoExterno {
    fn perguntar(&self, pergunta: &Pergunta) -> Option<BTreeMap<String, Segredo>> {
        // O stderr da janela vai para o do agente (o journal, no serviço):
        // é onde aparece a biblioteca que falta. A janela nunca escreve o
        // código ali.
        let mut filho = match Command::new(&self.programa)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(filho) => filho,
            Err(e) => {
                eprintln!(
                    "não deu para abrir a janela do OTP ({}): {e}",
                    self.programa.display()
                );
                return None;
            }
        };
        let entrada = serde_json::to_vec(pergunta).ok()?;
        let escrito = filho
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(&entrada).is_ok());
        let mut saida = filho.stdout.take()?;
        let (pronto, resposta) = mpsc::channel();
        std::thread::spawn(move || {
            let mut texto = Vec::new();
            let lido = saida.by_ref().take(RESPOSTA_MAXIMA).read_to_end(&mut texto);
            let _ = pronto.send(lido.map(|_| texto));
        });
        let texto = match resposta.recv_timeout(self.prazo) {
            Ok(Ok(texto)) => zeroize::Zeroizing::new(texto),
            _ => {
                let _ = filho.kill();
                let _ = filho.wait();
                return None;
            }
        };
        let estado = filho.wait().ok()?;
        // Sair com 1 é a pessoa fechando a janela; outro código é defeito.
        if !estado.success() {
            if estado.code() != Some(1) {
                eprintln!(
                    "a janela do OTP ({}) terminou com {estado}",
                    self.programa.display()
                );
            }
            return None;
        }
        if !escrito {
            return None;
        }
        serde_json::from_slice::<Valores>(&texto)
            .ok()
            .map(|v| v.valores)
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    fn programa(nome: &str, corpo: &str) -> PathBuf {
        let dir = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/testes/dialogo"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let caminho = dir.join(nome);
        std::fs::write(&caminho, format!("#!/bin/sh\n{corpo}\n")).unwrap();
        std::fs::set_permissions(&caminho, std::fs::Permissions::from_mode(0o700)).unwrap();
        caminho
    }

    fn pergunta() -> Pergunta {
        Pergunta {
            fatores: vec![FatorPedido {
                nome: "otp".into(),
                rotulo: "Código do autenticador".into(),
            }],
            recusa: None,
            certificado: Some("FULANO DE TAL".into()),
        }
    }

    #[test]
    fn a_janela_recebe_a_pergunta_no_stdin_e_responde_no_stdout() {
        // Responde só se a pergunta chegou com o fator certo.
        let janela = programa(
            "responde",
            r#"grep -q '"nome":"otp"' && echo '{"valores":{"otp":"123456"}}'"#,
        );
        let valores = DialogoExterno::novo(janela, PRAZO)
            .perguntar(&pergunta())
            .expect("respondeu");
        assert_eq!(valores["otp"].expor(), "123456");
    }

    #[test]
    fn fechar_a_janela_ou_responder_fora_do_formato_e_desistir() {
        for (nome, corpo) in [
            ("fecha", "cat >/dev/null; exit 1"),
            ("lixo", "cat >/dev/null; echo oi"),
            ("sem-programa", "exec /nao/existe"),
        ] {
            let janela = programa(nome, corpo);
            assert!(
                DialogoExterno::novo(janela, PRAZO)
                    .perguntar(&pergunta())
                    .is_none(),
                "{nome}"
            );
        }
        let ausente = DialogoExterno::novo("/nao/existe", PRAZO);
        assert!(ausente.perguntar(&pergunta()).is_none());
    }

    #[test]
    fn quem_nao_responde_no_prazo_desiste_e_a_janela_fecha() {
        let janela = programa("dorme", "cat >/dev/null; exec sleep 30");
        let comeco = Instant::now();
        let resposta =
            DialogoExterno::novo(janela, Duration::from_millis(300)).perguntar(&pergunta());
        assert!(resposta.is_none());
        assert!(
            comeco.elapsed() < Duration::from_secs(5),
            "não esperou o sleep"
        );
    }
}
