//! As regras da auditoria: cada mudança em quem pode assinar e cada tentativa
//! de PIN entram, nada secreto entra, o banco recusa alterar ou apagar, e quem
//! mexe por fora (com a chave na mão) quebra a corrente de selos.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use protocolo::Segredo;
use rusqlite::Connection;
use servidor::auditoria::{Lancamento, Verificacao};
use servidor::banco::{Banco, ChaveDoBanco, ler_chave, travar};
use servidor::pin::{self, FalhaDoPin};

const PIN: &str = "pessoal-8642";
const ERRADO: &str = "errado-1357";

fn diretorio(nome: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("auditoria-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("chave"),
        ChaveDoBanco::aleatorio().unwrap().expor(),
    )
    .unwrap();
    dir
}

fn abrir(dir: &Path) -> Banco {
    Banco::abrir(
        &dir.join("banco.db"),
        ler_chave(&dir.join("chave")).unwrap(),
    )
    .unwrap()
}

/// O banco aberto direto pelo SQLCipher, como alguém com a chave e o arquivo.
fn por_fora(dir: &Path) -> Connection {
    let chave = std::fs::read(dir.join("chave")).unwrap();
    let hex: String = chave.iter().map(|b| format!("{b:02x}")).collect();
    let conexao = Connection::open(dir.join("banco.db")).unwrap();
    conexao
        .execute_batch(&format!(
            "PRAGMA key = \"x'{hex}'\"; PRAGMA cipher_compatibility = 4;
             PRAGMA cipher_plaintext_header_size = 0;"
        ))
        .unwrap();
    conexao
}

/// Um banco com uma história: usuário, token, dispositivo, PIN errado e
/// certo, desbloqueio, revogação e uma assinatura.
fn com_historia(dir: &Path) -> Mutex<Banco> {
    let banco = Mutex::new(abrir(dir));
    let hash = pin::hash(&Segredo::novo(PIN.into())).unwrap();
    let maria = travar(&banco).criar_usuario("maria", &hash).unwrap();
    let token = travar(&banco)
        .criar_token("RemoteID", "driver-x", &[])
        .unwrap();
    travar(&banco)
        .configurado(token, &Default::default())
        .unwrap();
    let notebook = travar(&banco)
        .criar_dispositivo(maria, "notebook", b"chave do notebook")
        .unwrap();
    assert!(matches!(
        pin::conferir(&banco, notebook, &Segredo::novo(ERRADO.into())),
        Err(FalhaDoPin::Errado { .. })
    ));
    let autenticado = pin::conferir(&banco, notebook, &Segredo::novo(PIN.into())).unwrap();
    travar(&banco)
        .auditar_assinatura(&Lancamento {
            evento: "assinatura",
            usuario: Some(1),
            dispositivo: Some(1),
            token: Some("RemoteID".into()),
            chave: Some("k1".into()),
            mecanismo: Some("CKM_SHA256_RSA_PKCS".into()),
            resumo: Some([7; 32]),
            resultado: "assinada".into(),
        })
        .unwrap();
    assert_eq!(autenticado.dispositivo(), notebook);
    assert!(travar(&banco).desbloquear(notebook).unwrap());
    assert!(travar(&banco).revogar(notebook).unwrap());
    banco
}

#[test]
fn cada_mudanca_e_cada_tentativa_entram_em_ordem() {
    let dir = diretorio("historia");
    let banco = com_historia(&dir);
    let linhas = travar(&banco).auditoria(100).unwrap();
    let eventos: Vec<(&str, &str)> = linhas
        .iter()
        .map(|l| (l.evento.as_str(), l.resultado.as_str()))
        .collect();
    assert_eq!(
        eventos,
        [
            ("usuario_criado", "ok"),
            ("token_criado", "ok"),
            ("token_configurado", "ok"),
            ("dispositivo_criado", "ok"),
            ("entrada", "pin_errado"),
            ("entrada", "aceita"),
            ("assinatura", "assinada"),
            ("desbloqueio", "ok"),
            ("revogacao", "ok"),
        ]
    );
    assert!(linhas.iter().all(|l| l.id > 0 && l.quando_ms > 0));
    assert_eq!(linhas[4].usuario.as_deref(), Some("maria"));
    assert_eq!(linhas[4].dispositivo, Some(1));

    // As últimas `n`, ainda da mais antiga para a mais nova.
    let duas = travar(&banco).auditoria(2).unwrap();
    assert_eq!(
        duas.iter().map(|l| l.evento.as_str()).collect::<Vec<_>>(),
        ["desbloqueio", "revogacao"]
    );

    match travar(&banco).verificar_auditoria().unwrap() {
        Verificacao::Integra { linhas, .. } => assert_eq!(linhas, 9),
        quebrada => panic!("{quebrada:?}"),
    }
}

#[test]
fn nada_secreto_entra_na_auditoria() {
    let dir = diretorio("segredos");
    let banco = com_historia(&dir);
    let tudo = format!("{:?}", travar(&banco).auditoria(100).unwrap());
    for segredo in [PIN, ERRADO, "chave do notebook", "$argon2id$"] {
        assert!(!tudo.contains(segredo), "{segredo} na auditoria");
    }
}

#[test]
fn o_banco_recusa_alterar_e_apagar_a_auditoria() {
    let dir = diretorio("so-acrescimo");
    drop(com_historia(&dir));
    let conexao = por_fora(&dir);
    for sql in [
        "UPDATE auditoria SET resultado = 'aceita' WHERE id = 5",
        "DELETE FROM auditoria WHERE id = 5",
        "DELETE FROM auditoria",
    ] {
        let falha = conexao.execute(sql, []).unwrap_err().to_string();
        assert!(falha.contains("só de acréscimo"), "{sql}: {falha}");
    }
}

#[test]
fn mexer_por_fora_quebra_a_corrente_na_linha_mexida() {
    let dir = diretorio("por-fora");
    drop(com_historia(&dir));
    let conexao = por_fora(&dir);
    // Quem tem a chave tira os gatilhos e troca o PIN errado por um acerto.
    conexao
        .execute_batch(
            "DROP TRIGGER auditoria_sem_alteracao;
             UPDATE auditoria SET resultado = 'aceita' WHERE id = 5;",
        )
        .unwrap();
    drop(conexao);
    assert_eq!(
        abrir(&dir).verificar_auditoria().unwrap(),
        Verificacao::Quebrada { id: 5 }
    );

    // Apagar uma linha do meio também aparece.
    let dir = diretorio("por-fora-apagada");
    drop(com_historia(&dir));
    let conexao = por_fora(&dir);
    conexao
        .execute_batch(
            "DROP TRIGGER auditoria_sem_remocao;
             DELETE FROM auditoria WHERE id = 7;",
        )
        .unwrap();
    drop(conexao);
    assert_eq!(
        abrir(&dir).verificar_auditoria().unwrap(),
        Verificacao::Quebrada { id: 8 }
    );
}

#[test]
fn o_backup_leva_a_auditoria_inteira_e_os_gatilhos() {
    let dir = diretorio("backup");
    let banco = com_historia(&dir);
    let original = travar(&banco).verificar_auditoria().unwrap();
    travar(&banco).backup(&dir.join("copia.db")).unwrap();

    let copia = Banco::abrir(
        &dir.join("copia.db"),
        ler_chave(&dir.join("chave")).unwrap(),
    )
    .unwrap();
    assert_eq!(copia.verificar_auditoria().unwrap(), original);
    drop(copia);
    let chave = std::fs::read(dir.join("chave")).unwrap();
    let hex: String = chave.iter().map(|b| format!("{b:02x}")).collect();
    let conexao = Connection::open(dir.join("copia.db")).unwrap();
    conexao
        .execute_batch(&format!(
            "PRAGMA key = \"x'{hex}'\"; PRAGMA cipher_plaintext_header_size = 0;"
        ))
        .unwrap();
    assert!(conexao.execute("DELETE FROM auditoria", []).is_err());
}
