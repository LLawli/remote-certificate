//! Quem responde cada fator que um driver pede.
//!
//! Os fatores `guardado` saem do cofre do servidor e os `da_pessoa`, de quem
//! pediu a operação. A pessoa nunca responde um fator guardado, e um fator
//! guardado que o token pede de novo depois de uma recusa nunca é reenviado:
//! um token físico trava depois de poucas tentativas.

use std::collections::BTreeMap;

use protocolo::{Fator, PedidoDeFatores, Segredo, TipoDeFator};

/// Quem pediu a operação: digita os fatores `da_pessoa` (o OTP).
pub trait Pessoa {
    /// `None` é desistir.
    fn pedir(
        &mut self,
        fatores: &[&Fator],
        recusa: Option<&str>,
    ) -> Option<BTreeMap<String, Segredo>>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decisao {
    Responder(BTreeMap<String, Segredo>),
    Cancelar(Motivo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    /// O driver pediu um fator que não declarou na apresentação.
    FatorDesconhecido(String),
    /// O cofre não tem um fator guardado que o driver pediu.
    GuardadoAusente(String),
    /// O token recusou e pede de novo estes fatores guardados: o segredo no
    /// cofre está desatualizado, e reenviá-lo só gastaria tentativas.
    GuardadoRecusado(Vec<String>),
    PessoaDesistiu,
    /// A pessoa não respondeu todos os fatores pedidos.
    RespostaIncompleta(String),
}

pub fn decidir(
    declarados: &[Fator],
    pedido: &PedidoDeFatores,
    cofre: &BTreeMap<String, Segredo>,
    pessoa: &mut dyn Pessoa,
) -> Decisao {
    let mut guardados = Vec::new();
    let mut da_pessoa = Vec::new();
    for nome in &pedido.fatores {
        match declarados.iter().find(|f| &f.nome == nome) {
            None => return Decisao::Cancelar(Motivo::FatorDesconhecido(nome.clone())),
            Some(f) if f.tipo == TipoDeFator::Guardado => guardados.push(f),
            Some(f) => da_pessoa.push(f),
        }
    }

    // Um driver só repete um fator guardado depois de uma recusa quando foi
    // ele que o token recusou (docs/drivers.md), mesmo que peça também um da
    // pessoa: o RemoteID pede o PIN e o OTP de novo quando o PIN não abre.
    if pedido.recusa.is_some() && !guardados.is_empty() {
        let nomes = guardados.iter().map(|f| f.nome.clone()).collect();
        return Decisao::Cancelar(Motivo::GuardadoRecusado(nomes));
    }

    let mut resposta = BTreeMap::new();
    for f in &guardados {
        match cofre.get(&f.nome) {
            Some(valor) => resposta.insert(f.nome.clone(), valor.clone()),
            None => return Decisao::Cancelar(Motivo::GuardadoAusente(f.nome.clone())),
        };
    }

    if !da_pessoa.is_empty() {
        let Some(mut digitados) = pessoa.pedir(&da_pessoa, pedido.recusa.as_deref()) else {
            return Decisao::Cancelar(Motivo::PessoaDesistiu);
        };
        // Só o que foi pedido à pessoa sai do que ela mandou: um valor com o
        // nome de um fator guardado é descartado aqui.
        for f in &da_pessoa {
            match digitados.remove(&f.nome) {
                Some(valor) => resposta.insert(f.nome.clone(), valor),
                None => return Decisao::Cancelar(Motivo::RespostaIncompleta(f.nome.clone())),
            };
        }
    }
    Decisao::Responder(resposta)
}

/// O que o servidor guarda depois de um `configurar`: os campos com o nome de
/// um fator guardado e o que o driver gerou para guardar.
pub fn a_guardar(
    declarados: &[Fator],
    valores: &BTreeMap<String, Segredo>,
    gerados: BTreeMap<String, Segredo>,
) -> BTreeMap<String, Segredo> {
    let mut cofre: BTreeMap<String, Segredo> = valores
        .iter()
        .filter(|(nome, _)| {
            declarados
                .iter()
                .any(|f| &f.nome == *nome && f.tipo == TipoDeFator::Guardado)
        })
        .map(|(nome, valor)| (nome.clone(), valor.clone()))
        .collect();
    cofre.extend(gerados.into_iter().filter(|(nome, _)| {
        declarados
            .iter()
            .any(|f| &f.nome == nome && f.tipo == TipoDeFator::Guardado)
    }));
    cofre
}

#[cfg(test)]
mod testes {
    use super::*;

    fn fator(nome: &str, tipo: TipoDeFator) -> Fator {
        Fator {
            nome: nome.into(),
            tipo,
            rotulo: nome.into(),
        }
    }

    fn declarados() -> Vec<Fator> {
        vec![
            fator("pin", TipoDeFator::Guardado),
            fator("otp", TipoDeFator::DaPessoa),
        ]
    }

    fn mapa(pares: &[(&str, &str)]) -> BTreeMap<String, Segredo> {
        pares
            .iter()
            .map(|(k, v)| (k.to_string(), Segredo::novo(v.to_string())))
            .collect()
    }

    fn pedido(fatores: &[&str], recusa: Option<&str>) -> PedidoDeFatores {
        PedidoDeFatores {
            fatores: fatores.iter().map(|f| f.to_string()).collect(),
            recusa: recusa.map(str::to_string),
        }
    }

    /// Responde sempre o mesmo mapa e conta quantas vezes foi perguntada.
    struct Roteiro {
        resposta: Option<BTreeMap<String, Segredo>>,
        perguntas: Vec<(Vec<String>, Option<String>)>,
    }

    impl Roteiro {
        fn novo(resposta: Option<BTreeMap<String, Segredo>>) -> Self {
            Roteiro {
                resposta,
                perguntas: Vec::new(),
            }
        }
    }

    impl Pessoa for Roteiro {
        fn pedir(
            &mut self,
            fatores: &[&Fator],
            recusa: Option<&str>,
        ) -> Option<BTreeMap<String, Segredo>> {
            self.perguntas.push((
                fatores.iter().map(|f| f.nome.clone()).collect(),
                recusa.map(str::to_string),
            ));
            self.resposta.clone()
        }
    }

    #[test]
    fn guardado_vem_do_cofre_e_otp_da_pessoa() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "123456")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin", "otp"], None),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Responder(mapa(&[("pin", "4321"), ("otp", "123456")]))
        );
        assert_eq!(pessoa.perguntas, [(vec!["otp".to_string()], None)]);
    }

    #[test]
    fn a_pessoa_nao_substitui_um_fator_guardado() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "123456"), ("pin", "0000")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin", "otp"], None),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Responder(mapa(&[("pin", "4321"), ("otp", "123456")]))
        );
    }

    #[test]
    fn so_guardado_sem_recusa_nao_pergunta_a_pessoa() {
        let mut pessoa = Roteiro::novo(None);
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin"], None),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert_eq!(decisao, Decisao::Responder(mapa(&[("pin", "4321")])));
        assert!(pessoa.perguntas.is_empty());
    }

    #[test]
    fn guardado_recusado_nao_tem_segunda_tentativa() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "123456")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin"], Some("PIN incorreto")),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Cancelar(Motivo::GuardadoRecusado(vec!["pin".into()]))
        );
        assert!(pessoa.perguntas.is_empty());
    }

    #[test]
    fn guardado_pedido_de_novo_junto_com_o_da_pessoa_nao_e_reenviado() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "654321")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin", "otp"], Some("PIN incorreto")),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Cancelar(Motivo::GuardadoRecusado(vec!["pin".into()]))
        );
        assert!(pessoa.perguntas.is_empty());
    }

    #[test]
    fn recusa_so_com_fator_da_pessoa_pergunta_de_novo_com_a_mensagem() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "654321")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["otp"], Some("PIN ou e-Token incorreto")),
            &mapa(&[("pin", "4321")]),
            &mut pessoa,
        );
        assert!(matches!(decisao, Decisao::Responder(_)));
        assert_eq!(
            pessoa.perguntas,
            [(
                vec!["otp".to_string()],
                Some("PIN ou e-Token incorreto".into())
            )]
        );
    }

    #[test]
    fn fator_nao_declarado_cancela() {
        let mut pessoa = Roteiro::novo(None);
        let decisao = decidir(
            &declarados(),
            &pedido(&["senha"], None),
            &mapa(&[]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Cancelar(Motivo::FatorDesconhecido("senha".into()))
        );
    }

    #[test]
    fn cofre_sem_o_fator_cancela_antes_de_perguntar() {
        let mut pessoa = Roteiro::novo(Some(mapa(&[("otp", "123456")])));
        let decisao = decidir(
            &declarados(),
            &pedido(&["pin", "otp"], None),
            &mapa(&[]),
            &mut pessoa,
        );
        assert_eq!(
            decisao,
            Decisao::Cancelar(Motivo::GuardadoAusente("pin".into()))
        );
        assert!(pessoa.perguntas.is_empty(), "o OTP não pode ser gasto");
    }

    #[test]
    fn pessoa_que_desiste_ou_esquece_um_fator_cancela() {
        let mut desiste = Roteiro::novo(None);
        let cofre = mapa(&[("pin", "4321")]);
        let pede = pedido(&["pin", "otp"], None);
        assert_eq!(
            decidir(&declarados(), &pede, &cofre, &mut desiste),
            Decisao::Cancelar(Motivo::PessoaDesistiu)
        );
        let mut esquece = Roteiro::novo(Some(mapa(&[])));
        assert_eq!(
            decidir(&declarados(), &pede, &cofre, &mut esquece),
            Decisao::Cancelar(Motivo::RespostaIncompleta("otp".into()))
        );
    }

    #[test]
    fn configurar_guarda_so_fatores_guardados() {
        let valores = mapa(&[("email", "a@b"), ("pin", "4321"), ("otp", "1")]);
        let gerados = mapa(&[("pin", "9999"), ("otp", "2"), ("outro", "x")]);
        assert_eq!(
            a_guardar(&declarados(), &valores, gerados),
            mapa(&[("pin", "9999")]),
            "o gerado pelo driver vence, e nada que não seja fator guardado entra"
        );
        assert_eq!(
            a_guardar(&declarados(), &valores, BTreeMap::new()),
            mapa(&[("pin", "4321")])
        );
    }
}
