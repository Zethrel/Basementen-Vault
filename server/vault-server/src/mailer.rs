use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::sync::Mutex;

use crate::config::MailConfig;

#[derive(Debug, Clone)]
pub struct OutgoingMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// E-mail delivery backend.
pub enum Mailer {
    /// Print to the server log (default; fine for VPN-only home setups).
    Console,
    /// Deliver through an SMTP relay. Boxed: the transport is large and this
    /// enum is kept small for the common Console case.
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
    },
    /// Capture in memory; used by the integration tests.
    Memory(Mutex<Vec<OutgoingMail>>),
}

impl Mailer {
    pub fn from_config(cfg: &MailConfig) -> Result<Self, String> {
        match cfg {
            MailConfig::Console => {
                // The console mailer writes full e-mail bodies — including
                // verification and account-recovery links — to the server log.
                // That is the point (it is how an operator without SMTP reads
                // the link), but those links are sensitive, so make the
                // tradeoff loud instead of silent. Configure `BV_MAILER=smtp`
                // for any deployment whose logs are shipped or shared.
                tracing::warn!(
                    "console mailer active: verification and recovery links are \
                     written to the server log — do not use with exported/shared \
                     logs; set BV_MAILER=smtp for real delivery"
                );
                Ok(Mailer::Console)
            }
            MailConfig::Smtp {
                host,
                port,
                username,
                password,
                from,
                implicit_tls,
            } => {
                let mut builder = if *implicit_tls {
                    AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                } else {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                }
                .map_err(|e| format!("SMTP relay config: {e}"))?
                .port(*port);
                if !username.is_empty() {
                    builder =
                        builder.credentials(Credentials::new(username.clone(), password.clone()));
                }
                Ok(Mailer::Smtp {
                    transport: Box::new(builder.build()),
                    from: from.parse().map_err(|e| format!("BV_SMTP_FROM: {e}"))?,
                })
            }
        }
    }

    /// Send an e-mail. Failures are logged but never returned to API callers:
    /// mail delivery problems must not turn into user-visible oracles about
    /// which accounts exist.
    pub async fn send(&self, to: &str, subject: &str, body: &str) {
        match self {
            Mailer::Console => {
                tracing::info!(to, subject, body, "outgoing e-mail (console mailer)");
            }
            Mailer::Smtp { transport, from } => {
                let msg = Mailbox::try_from((String::new(), to.to_string()))
                    .map_err(|e| e.to_string())
                    .and_then(|to_mb| {
                        Message::builder()
                            .from(from.clone())
                            .to(to_mb)
                            .subject(subject)
                            .body(body.to_string())
                            .map_err(|e| e.to_string())
                    });
                match msg {
                    Ok(msg) => {
                        if let Err(e) = transport.send(msg).await {
                            tracing::error!(error = %e, to, subject, "SMTP send failed");
                        }
                    }
                    Err(e) => tracing::error!(error = %e, to, "could not build e-mail"),
                }
            }
            Mailer::Memory(store) => {
                store
                    .lock()
                    .expect("mailer mutex poisoned")
                    .push(OutgoingMail {
                        to: to.to_string(),
                        subject: subject.to_string(),
                        body: body.to_string(),
                    });
            }
        }
    }

    /// Test helper: everything sent so far (Memory mailer only).
    pub fn sent(&self) -> Vec<OutgoingMail> {
        match self {
            Mailer::Memory(store) => store.lock().expect("mailer mutex poisoned").clone(),
            _ => Vec::new(),
        }
    }
}
