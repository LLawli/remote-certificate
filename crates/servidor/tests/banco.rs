//! As regras do banco: nada em claro no disco, nenhum banco em claro aberto,
//! chave errada indistinguível de arquivo corrompido, o estado de um token
//! parado gravado, e backup que só existe se confere.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use protocolo::Segredo;
use servidor::banco::{Banco, ChaveDoBanco, FalhaDoBanco, ler_chave};

/// Um valor que só pode aparecer no disco se vazar.
const PIN: &str = "pin-que-nunca-aparece-0815";

fn diretorio(nome: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("banco-{nome}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Uma chave que dá para usar de novo: o banco fica com a dele.
fn chave(dir: &Path) -> ChaveDoBanco {
    let arquivo = dir.join("chave");
    if !arquivo.exists() {
        std::fs::write(&arquivo, ChaveDoBanco::aleatorio().unwrap().expor()).unwrap();
    }
    ler_chave(&arquivo).unwrap()
}

fn cofre(pin: &str) -> BTreeMap<String, Segredo> {
    BTreeMap::from([("pin".to_string(), Segredo::novo(pin.into()))])
}

fn modo(caminho: &Path) -> u32 {
    std::fs::metadata(caminho).unwrap().permissions().mode() & 0o777
}

#[test]
fn nada_em_claro_no_arquivo_do_banco() {
    let dir = diretorio("em-claro");
    let caminho = dir.join("banco.db");
    let banco = Banco::abrir(&caminho, chave(&dir)).unwrap();
    let token = banco
        .criar_token("Token do escritório", "driver-x", &[])
        .unwrap();
    banco.configurado(token, &cofre(PIN)).unwrap();
    drop(banco);

    let bruto = std::fs::read(&caminho).unwrap();
    assert!(bruto.len() > 4096, "o banco tem pelo menos uma página");
    let texto = String::from_utf8_lossy(&bruto);
    for vazamento in [
        PIN,
        "Token do escritório",
        "fator_guardado",
        "SQLite format 3",
    ] {
        assert!(!texto.contains(vazamento), "{vazamento} em claro no banco");
    }
    assert_eq!(modo(&caminho), 0o600);
}

#[test]
fn banco_em_claro_nao_abre() {
    let dir = diretorio("sem-cifra");
    let caminho = dir.join("banco.db");
    let claro = rusqlite::Connection::open(&caminho).unwrap();
    claro
        .execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    drop(claro);
    assert!(
        std::fs::read(&caminho)
            .unwrap()
            .starts_with(b"SQLite format 3\0")
    );

    let falha = Banco::abrir(&caminho, chave(&dir));
    assert!(matches!(falha, Err(FalhaDoBanco::EmClaro)));
}

#[test]
fn chave_errada_e_arquivo_corrompido_dao_o_mesmo_erro() {
    let dir = diretorio("chave-errada");
    let caminho = dir.join("banco.db");
    drop(Banco::abrir(&caminho, chave(&dir)).unwrap());

    let outra = ChaveDoBanco::aleatorio().unwrap();
    assert!(matches!(
        Banco::abrir(&caminho, outra),
        Err(FalhaDoBanco::ChaveOuArquivo)
    ));

    let lixo = dir.join("lixo.db");
    std::fs::write(&lixo, vec![0x5a; 8192]).unwrap();
    assert!(matches!(
        Banco::abrir(&lixo, chave(&dir)),
        Err(FalhaDoBanco::ChaveOuArquivo)
    ));
}

#[test]
fn chave_de_tamanho_errado_e_recusada() {
    let dir = diretorio("chave-curta");
    let arquivo = dir.join("chave");
    std::fs::write(&arquivo, b"uma senha qualquer\n").unwrap();
    assert!(matches!(
        ler_chave(&arquivo),
        Err(FalhaDoBanco::ChaveMalFormada)
    ));
}

#[test]
fn token_parado_continua_parado_ao_reabrir_e_configurar_libera() {
    let dir = diretorio("parado");
    let caminho = dir.join("banco.db");
    let banco = Banco::abrir(&caminho, chave(&dir)).unwrap();
    let token = banco.criar_token("t", "driver-x", &["--a".into()]).unwrap();
    banco.configurado(token, &cofre(PIN)).unwrap();
    banco.marcar_desatualizado(token, &["pin".into()]).unwrap();
    drop(banco);

    let banco = Banco::abrir(&caminho, chave(&dir)).unwrap();
    assert_eq!(
        banco.desatualizado(token).unwrap(),
        Some(vec!["pin".to_string()])
    );
    assert_eq!(banco.cofre(token).unwrap()["pin"].expor(), PIN);
    assert_eq!(banco.tokens().unwrap()[0].argumentos, ["--a"]);

    banco.configurado(token, &cofre("outro")).unwrap();
    assert_eq!(banco.desatualizado(token).unwrap(), None);
    assert_eq!(banco.cofre(token).unwrap()["pin"].expor(), "outro");
}

#[test]
fn backup_cifrado_que_confere_e_abre_com_a_mesma_chave() {
    let dir = diretorio("backup");
    let banco = Banco::abrir(&dir.join("banco.db"), chave(&dir)).unwrap();
    let token = banco.criar_token("t", "driver-x", &[]).unwrap();
    banco.configurado(token, &cofre(PIN)).unwrap();

    let copia = dir.join("copia.db");
    banco.backup(&copia).unwrap();
    assert_eq!(modo(&copia), 0o600);
    let texto = String::from_utf8_lossy(&std::fs::read(&copia).unwrap()).into_owned();
    assert!(!texto.contains(PIN) && !texto.contains("SQLite format 3"));

    let restaurado = Banco::abrir(&copia, chave(&dir)).unwrap();
    assert_eq!(restaurado.cofre(token).unwrap()["pin"].expor(), PIN);

    // Um backup nunca sobrescreve outro.
    assert!(matches!(
        banco.backup(&copia),
        Err(FalhaDoBanco::JaExiste(_))
    ));
}
