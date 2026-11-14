//! `remote-certificate-dialogo`: a janela que o agente abre no meio de uma
//! assinatura, quando o token pede um fator da pessoa (o OTP). Lê a
//! [`Pergunta`] do stdin, escreve os [`Valores`] no stdout e sai com 0;
//! fechar a janela (ou Esc) sai com 1, e o agente entende como desistência.
//!
//! Sem `application_id`: a janela não se registra no barramento, e assim abre
//! também dentro de um sandbox que não pode ter um nome nele.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use ipc::janela::{Pergunta, Valores};
use protocolo::Segredo;

/// A maior pergunta que a janela lê.
const PERGUNTA_MAXIMA: u64 = 64 * 1024;
const TITULO: &str = "Assinatura";

fn main() -> ExitCode {
    let mut texto = Vec::new();
    let lida = std::io::stdin()
        .take(PERGUNTA_MAXIMA)
        .read_to_end(&mut texto);
    let Some(pergunta) = lida
        .ok()
        .and_then(|_| serde_json::from_slice::<Pergunta>(&texto).ok())
        .filter(|p| !p.fatores.is_empty())
    else {
        return ExitCode::FAILURE;
    };
    let app = adw::Application::builder()
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let respondido = Rc::new(Cell::new(false));
    let r = respondido.clone();
    app.connect_activate(move |app| montar(app, &pergunta, r.clone()));
    app.run_with_args::<&str>(&[]);
    if respondido.get() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// O nome e o documento de um titular da ICP-Brasil, que vêm juntos no CN
/// (`FULANO DE TAL:12345678901`).
fn titular(certificado: &str) -> (&str, Option<&str>) {
    match certificado.rsplit_once(':') {
        Some((nome, documento))
            if !nome.is_empty()
                && !documento.is_empty()
                && documento.chars().all(|c| c.is_ascii_digit()) =>
        {
            (nome, Some(documento))
        }
        _ => (certificado, None),
    }
}

/// Um código de autenticador se digita; uma senha se esconde.
fn e_codigo(nome: &str) -> bool {
    nome.eq_ignore_ascii_case("otp") || nome.contains("codigo")
}

fn montar(app: &adw::Application, pergunta: &Pergunta, respondido: Rc<Cell<bool>>) {
    let campos = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let mut linhas: Vec<(String, adw::EntryRow)> = Vec::new();
    for fator in &pergunta.fatores {
        let linha: adw::EntryRow = if e_codigo(&fator.nome) {
            let linha = adw::EntryRow::builder()
                .title(&fator.rotulo)
                .input_purpose(gtk::InputPurpose::Digits)
                .build();
            linha.add_prefix(&gtk::Image::from_icon_name("phone-symbolic"));
            linha
        } else {
            let linha = adw::PasswordEntryRow::builder()
                .title(&fator.rotulo)
                .build();
            linha.add_prefix(&gtk::Image::from_icon_name("dialog-password-symbolic"));
            linha.upcast()
        };
        if pergunta.recusa.is_some() {
            linha.add_css_class("error");
        }
        campos.append(&linha);
        linhas.push((fator.nome.clone(), linha));
    }

    let assinar = gtk::Button::builder()
        .halign(gtk::Align::Center)
        .sensitive(false)
        .css_classes(["suggested-action", "pill"])
        .child(
            &adw::ButtonContent::builder()
                .icon_name("document-edit-symbolic")
                .label("Assinar")
                .build(),
        )
        .build();

    let corpo = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(20)
        .margin_top(8)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    if let Some(certificado) = &pergunta.certificado {
        let (nome, documento) = titular(certificado);
        let titular = gtk::Box::builder()
            .spacing(12)
            .halign(gtk::Align::Center)
            .build();
        titular.append(
            &gtk::Image::builder()
                .icon_name("application-certificate-symbolic")
                .pixel_size(32)
                .build(),
        );
        let textos = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .valign(gtk::Align::Center)
            .build();
        textos.append(
            &gtk::Label::builder()
                .label(nome)
                .wrap(true)
                .xalign(0.0)
                .css_classes(["title-3"])
                .build(),
        );
        if let Some(documento) = documento {
            textos.append(
                &gtk::Label::builder()
                    .label(documento)
                    .xalign(0.0)
                    .css_classes(["dim-label", "numeric"])
                    .build(),
            );
        }
        titular.append(&textos);
        corpo.append(&titular);
    }
    corpo.append(&campos);
    corpo.append(&assinar);

    let conteudo = adw::ToolbarView::builder()
        .top_bar_style(adw::ToolbarStyle::Flat)
        .content(&corpo)
        .build();
    conteudo.add_top_bar(&adw::HeaderBar::builder().show_title(false).build());
    if let Some(recusa) = &pergunta.recusa {
        conteudo.add_top_bar(&adw::Banner::builder().title(recusa).revealed(true).build());
    }

    let janela = adw::ApplicationWindow::builder()
        .application(app)
        .title(pergunta.certificado.as_deref().unwrap_or(TITULO))
        .default_width(400)
        .resizable(false)
        .content(&conteudo)
        .build();

    let completo = {
        let linhas = linhas.clone();
        move || linhas.iter().all(|(_, l)| !l.text().trim().is_empty())
    };
    for (_, linha) in &linhas {
        let (assinar, completo, linhas) = (assinar.clone(), completo.clone(), linhas.clone());
        linha.connect_changed(move |_| {
            assinar.set_sensitive(completo());
            for (_, l) in &linhas {
                l.remove_css_class("error");
            }
        });
    }

    let responder = {
        let (linhas, janela, completo) = (linhas.clone(), janela.clone(), completo.clone());
        move || {
            if !completo() {
                return;
            }
            let valores: BTreeMap<String, Segredo> = linhas
                .iter()
                .map(|(nome, l)| (nome.clone(), Segredo::novo(l.text().trim().to_string())))
                .collect();
            let mut saida = std::io::stdout().lock();
            if serde_json::to_writer(&mut saida, &Valores { valores }).is_ok()
                && saida.flush().is_ok()
            {
                respondido.set(true);
            }
            janela.close();
        }
    };
    assinar.connect_clicked({
        let responder = responder.clone();
        move |_| responder()
    });
    // Enter passa ao próximo campo; no último, assina.
    for (i, (_, linha)) in linhas.iter().enumerate() {
        let proximo = linhas.get(i + 1).map(|(_, l)| l.clone());
        let responder = responder.clone();
        linha.connect_entry_activated(move |_| match &proximo {
            Some(l) => {
                l.grab_focus();
            }
            None => responder(),
        });
    }

    // Esc fecha, e fechar é desistir.
    let teclas = gtk::EventControllerKey::new();
    teclas.connect_key_pressed({
        let janela = janela.clone();
        move |_, tecla, _, _| {
            if tecla == gtk::gdk::Key::Escape {
                janela.close();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        }
    });
    janela.add_controller(teclas);

    janela.present();
    if let Some((_, primeira)) = linhas.first() {
        primeira.grab_focus();
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_cn_da_icp_brasil_separa_nome_e_documento() {
        assert_eq!(
            titular("FULANO DE TAL:12345678901"),
            ("FULANO DE TAL", Some("12345678901"))
        );
        assert_eq!(titular("ACME LTDA"), ("ACME LTDA", None));
        assert_eq!(titular("a:b"), ("a:b", None));
    }

    #[test]
    fn o_otp_e_um_codigo_e_o_resto_e_senha() {
        assert!(e_codigo("otp"));
        assert!(e_codigo("OTP"));
        assert!(!e_codigo("senha"));
    }
}
