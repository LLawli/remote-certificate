//! O servidor na rede, com clientes de verdade: o pareamento fixa as chaves
//! dos dois lados, uma chave desconhecida cai no handshake, e um código só vale
//! uma vez e por pouco tempo.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::header::HOST;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use protocolo::Segredo;
use rede::pareamento::{self, CodigoDePareamento, FalhaDoPareamento, Pareado};
use rede::tls::{self, Fixacao, Identidade};
use servidor::banco::{Banco, ChaveDoBanco, IdDoUsuario, ler_chave, travar};
use servidor::pin;
use servidor::servico::{self, agora};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Servidor {
    endereco: String,
    banco: Arc<Mutex<Banco>>,
    dir: PathBuf,
}

fn abrir(dir: &Path) -> Banco {
    Banco::abrir(
        &dir.join("banco.db"),
        ler_chave(&dir.join("chave")).unwrap(),
    )
    .unwrap()
}

async fn subir(nome: &str) -> Servidor {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("rede-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("chave"),
        ChaveDoBanco::aleatorio().unwrap().expor(),
    )
    .unwrap();
    let banco = Arc::new(Mutex::new(abrir(&dir)));
    let ouvinte = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endereco = ouvinte.local_addr().unwrap().to_string();
    tokio::spawn(servico::servir(ouvinte, banco.clone()));
    Servidor {
        endereco,
        banco,
        dir,
    }
}

impl Servidor {
    fn maria(&self) -> IdDoUsuario {
        let banco = travar(&self.banco);
        if let Some(maria) = banco.usuario("maria").unwrap() {
            return maria;
        }
        let hash = pin::hash(&Segredo::novo("2468".into())).unwrap();
        banco.criar_usuario("maria", &hash).unwrap()
    }

    fn codigo(&self, nome: &str) -> String {
        servico::novo_pareamento(&self.banco, self.maria(), nome)
            .unwrap()
            .to_string()
    }

    async fn parear(&self, nome: &str) -> (Identidade, Pareado) {
        let identidade = Identidade::gerar().unwrap();
        let pareado = pareamento::parear(&self.endereco, &self.codigo(nome), &identidade)
            .await
            .expect("pareia");
        (identidade, pareado)
    }
}

const RECUSADA: &str = "o servidor recusou a chave no handshake";

/// Um `GET` numa conexão nova: o status, ou por que não houve resposta.
async fn pedir(
    endereco: &str,
    identidade: &Identidade,
    fixacao: Fixacao,
    caminho: &str,
) -> Result<StatusCode, String> {
    let conexao = pareamento::conectar(endereco, identidade, fixacao)
        .await
        .map_err(|e| e.to_string())?;
    let (mut envio, conversa) = hyper::client::conn::http1::handshake(TokioIo::new(conexao))
        .await
        .map_err(|e| e.to_string())?;
    let conversa = tokio::spawn(conversa);
    let pedido = Request::get(caminho)
        .header(HOST, "remote-certificate")
        .body(Empty::<Bytes>::new())
        .unwrap();
    match envio.send_request(pedido).await {
        Ok(resposta) => Ok(resposta.status()),
        Err(e) => {
            let causa = conversa.await.unwrap().err().unwrap_or(e);
            Err(if tls::recusaram_a_nossa_chave(&causa) {
                RECUSADA.into()
            } else {
                causa.to_string()
            })
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pareado_conecta_com_as_duas_chaves_fixadas() {
    let servidor = subir("pareado").await;
    let (identidade, pareado) = servidor.parear("notebook").await;

    let identidade_do_servidor = servico::identidade(&servidor.banco).unwrap();
    assert_eq!(pareado.servidor, identidade_do_servidor.impressao());
    let dispositivos = travar(&servidor.banco).dispositivos().unwrap();
    assert_eq!(dispositivos.len(), 1);
    assert_eq!(
        dispositivos[0].id.to_string(),
        pareado.dispositivo.to_string()
    );
    assert_eq!(
        (
            dispositivos[0].usuario.as_str(),
            dispositivos[0].nome.as_str()
        ),
        ("maria", "notebook")
    );

    // Reconhecido como dispositivo: passa do pareamento para o resto da API.
    let status = pedir(
        &servidor.endereco,
        &identidade,
        Fixacao::Completa(pareado.servidor),
        "/v1/nada",
    )
    .await;
    assert_eq!(status, Ok(StatusCode::NOT_FOUND));
}

#[tokio::test(flavor = "multi_thread")]
async fn chave_desconhecida_cai_antes_de_qualquer_http() {
    let servidor = subir("desconhecida").await;
    let (_, pareado) = servidor.parear("notebook").await;

    let estranha = Identidade::gerar().unwrap();
    let status = pedir(
        &servidor.endereco,
        &estranha,
        Fixacao::Completa(pareado.servidor),
        "/v1/nada",
    )
    .await;
    assert_eq!(status, Err(RECUSADA.into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn com_pareamento_pendente_a_chave_nova_so_alcanca_o_pareamento() {
    let servidor = subir("pendente").await;
    let codigo = servidor.codigo("notebook");
    let comeco = CodigoDePareamento::ler(&codigo).unwrap().impressao;

    let nova = Identidade::gerar().unwrap();
    let status = pedir(
        &servidor.endereco,
        &nova,
        Fixacao::Pareamento(comeco),
        "/v1/nada",
    )
    .await;
    assert_eq!(status, Ok(StatusCode::FORBIDDEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn o_codigo_so_vale_uma_vez() {
    let servidor = subir("uma-vez").await;
    let codigo = servidor.codigo("notebook");
    // Outro pendente, para a segunda tentativa passar do handshake.
    let _outro = servidor.codigo("desktop");

    let primeira = Identidade::gerar().unwrap();
    pareamento::parear(&servidor.endereco, &codigo, &primeira)
        .await
        .unwrap();
    let segunda = Identidade::gerar().unwrap();
    let falha = pareamento::parear(&servidor.endereco, &codigo, &segunda).await;
    assert!(
        matches!(falha, Err(FalhaDoPareamento::Recusado)),
        "{falha:?}"
    );
    assert_eq!(travar(&servidor.banco).dispositivos().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn segredo_errado_e_recusado() {
    let servidor = subir("segredo-errado").await;
    let certo = CodigoDePareamento::ler(&servidor.codigo("notebook")).unwrap();
    let errado = CodigoDePareamento {
        impressao: certo.impressao,
        segredo: Zeroizing::new([0x55; pareamento::TAMANHO_DO_SEGREDO]),
    };
    let falha = pareamento::parear(
        &servidor.endereco,
        &errado.escrever(),
        &Identidade::gerar().unwrap(),
    )
    .await;
    assert!(
        matches!(falha, Err(FalhaDoPareamento::Recusado)),
        "{falha:?}"
    );
    assert!(travar(&servidor.banco).dispositivos().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn codigo_vencido_nao_abre_a_porta() {
    let servidor = subir("vencido").await;
    let codigo =
        CodigoDePareamento::novo(&servico::identidade(&servidor.banco).unwrap().impressao())
            .unwrap();
    let segredo: [u8; 32] = Sha256::digest(codigo.segredo.as_ref()).into();
    let maria = servidor.maria();
    travar(&servidor.banco)
        .criar_pareamento(&segredo, maria, "notebook", agora() - 1)
        .unwrap();

    let falha = pareamento::parear(
        &servidor.endereco,
        &codigo.escrever(),
        &Identidade::gerar().unwrap(),
    )
    .await;
    // Sem pendente válido, a chave nova cai no handshake.
    assert!(
        matches!(falha, Err(FalhaDoPareamento::Recusado)),
        "{falha:?}"
    );
    assert!(travar(&servidor.banco).dispositivos().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn o_cliente_recusa_um_servidor_que_nao_e_o_do_codigo() {
    let verdadeiro = subir("verdadeiro").await;
    let impostor = subir("impostor").await;
    let codigo = verdadeiro.codigo("notebook");
    // O impostor também espera um pareamento, então deixaria entrar.
    let _isca = impostor.codigo("notebook");

    let falha =
        pareamento::parear(&impostor.endereco, &codigo, &Identidade::gerar().unwrap()).await;
    assert!(
        matches!(falha, Err(FalhaDoPareamento::ServidorDiferente)),
        "{falha:?}"
    );
    assert!(travar(&impostor.banco).dispositivos().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_identidade_do_servidor_sobrevive_ao_reinicio() {
    let servidor = subir("identidade").await;
    let antes = servico::identidade(&servidor.banco).unwrap().impressao();
    let reaberto = Mutex::new(abrir(&servidor.dir));
    assert_eq!(servico::identidade(&reaberto).unwrap().impressao(), antes);
}
