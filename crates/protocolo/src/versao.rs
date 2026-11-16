//! A versão do contrato e quais versões de driver o servidor aceita.
//!
//! Cada versão declara as anteriores com que é compatível. O servidor aceita
//! um driver quando chega à versão dele seguindo essas declarações a partir da
//! sua: a compatibilidade é transitiva. Uma versão que não declara a anterior
//! é uma breaking change e corta a cadeia. Um driver mais novo que o servidor é
//! sempre recusado: o servidor só conhece a tabela até a própria versão.

/// Versão do contrato que este código fala. Muda quando uma mensagem muda de
/// forma incompatível; campo novo e opcional não muda a versão.
pub const VERSAO: u32 = 0;

/// Cada versão do contrato, da primeira à [`VERSAO`], com as versões
/// anteriores que ela declara compatíveis. Uma versão nova entra no fim.
pub const COMPATIBILIDADE: &[(u32, &[u32])] = &[(0, &[])];

/// Se o servidor nesta [`VERSAO`] aceita um driver que fala o contrato
/// `driver`.
pub fn aceita_driver(driver: u32) -> bool {
    alcanca(COMPATIBILIDADE, VERSAO, driver)
}

/// Se `driver` é alcançável a partir de `servidor` seguindo as declarações de
/// `tabela`.
fn alcanca(tabela: &[(u32, &[u32])], servidor: u32, driver: u32) -> bool {
    if driver > servidor {
        return false;
    }
    let mut pendentes = vec![servidor];
    let mut vistas = Vec::new();
    while let Some(versao) = pendentes.pop() {
        if versao == driver {
            return true;
        }
        if vistas.contains(&versao) {
            continue;
        }
        vistas.push(versao);
        if let Some((_, declaradas)) = tabela.iter().find(|(v, _)| *v == versao) {
            pendentes.extend(declaradas.iter().filter(|&&d| d < versao && d >= driver));
        }
    }
    false
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O exemplo da decisão: do v5 ao v10 cada versão declara a anterior, e o
    /// v5 foi uma breaking change.
    const CADEIA: &[(u32, &[u32])] = &[
        (3, &[]),
        (4, &[3]),
        (5, &[]),
        (6, &[5]),
        (7, &[6]),
        (8, &[7]),
        (9, &[8]),
        (10, &[9]),
    ];

    #[test]
    fn a_propria_versao_e_aceita() {
        assert!(alcanca(CADEIA, 10, 10));
        assert!(alcanca(CADEIA, 5, 5));
        assert!(aceita_driver(VERSAO));
    }

    #[test]
    fn a_versao_declarada_e_aceita() {
        assert!(alcanca(CADEIA, 10, 9));
        assert!(alcanca(CADEIA, 4, 3));
    }

    #[test]
    fn a_compatibilidade_e_transitiva() {
        assert!(alcanca(CADEIA, 10, 5));
        assert!(alcanca(CADEIA, 8, 6));
    }

    #[test]
    fn breaking_change_corta_a_cadeia() {
        assert!(!alcanca(CADEIA, 10, 4));
        assert!(!alcanca(CADEIA, 5, 4));
        assert!(!alcanca(CADEIA, 6, 3));
    }

    #[test]
    fn driver_mais_novo_e_recusado() {
        assert!(!alcanca(CADEIA, 5, 10));
        assert!(!alcanca(CADEIA, 9, 10));
        assert!(!aceita_driver(VERSAO + 1));
    }

    #[test]
    fn declaracao_que_pula_versoes_vale() {
        let tabela: &[(u32, &[u32])] = &[(1, &[]), (2, &[]), (3, &[1])];
        assert!(alcanca(tabela, 3, 1));
        assert!(!alcanca(tabela, 3, 2));
    }

    #[test]
    fn a_tabela_do_contrato_e_coerente() {
        // Uma entrada por versão, em ordem, da 0 à atual, e cada uma só
        // declara versões anteriores a ela.
        assert_eq!(COMPATIBILIDADE.len() as u32, VERSAO + 1);
        for (i, (versao, declaradas)) in COMPATIBILIDADE.iter().enumerate() {
            assert_eq!(*versao, i as u32);
            assert!(declaradas.iter().all(|d| d < versao), "v{versao}");
        }
    }
}
