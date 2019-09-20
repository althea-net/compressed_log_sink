#[macro_use]
extern crate log;
extern crate env_logger;
extern crate serde_derive;
use actix::*;
use actix_web::{server, ws, App};
use lz4::Decoder;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::fs::OpenOptions;
use std::io;

/// Define http actor
struct Ws {
    write: Box<dyn io::Write>,
}

impl Default for Ws {
    fn default() -> Self {
        Self {
            write: Box::new(io::stdout()),
        }
    }
}

impl Ws {
    pub fn new(write: Box<dyn io::Write>) -> Self {
        Self { write }
    }
}

impl Actor for Ws {
    type Context = ws::WebsocketContext<Self>;
}

/// Handler for ws::Message message
impl StreamHandler<ws::Message, ws::ProtocolError> for Ws {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        match msg {
            ws::Message::Ping(msg) => {
                debug!("Got ping, responding with pong");
                ctx.pong(&msg)
            }
            ws::Message::Text(_text) => (),
            ws::Message::Binary(mut bin) => {
                debug!("Got binary, dumping");
                let bytes = bin.take().to_vec();
                let mut decoder = Decoder::new(&bytes[..]).expect("Unable to create decoder");
                let mut output = Vec::new();
                // Extract data from decoder
                io::copy(&mut decoder, &mut output)
                    .expect("Unable to copy data from decoder to output buffer");

                // Don't fail if the data can't be written to the output stream
                println!("Write data to a stream... {} bytes", output.len());
                if let Err(err) = self.write.write(&output) {
                    eprintln!("Unable to write data to a stream: {}", err);
                } else {
                    // Otherwise flush the write.Actor
                    // This should make multiple opened file streams
                    // to not overleap their writes with others.
                    let _ = self.write.flush();
                }
            }
            _ => println!("Unknown message"),
        }
    }
}

use docopt::Docopt;

const USAGE: &str = r#"
Compressed log sink.

Usage:
  compressed_log_sink [ --bind=<address> ] [ --output=<stream> ] --cert=<cert-path> --key=<key-path>
  compressed_log_sink (-h | --help)
  compressed_log_sink --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --bind=<address>  Bind to address [default: 0.0.0.0:9999].
  --output=<stream>  Output stream [default: stdout].
  --cert=<path>     Https certificate chain.
  --key=<path>     Https keyfile.
"#;

fn main() {
    env_logger::init();
    info!("Compressed log sink starting!");
    let args = Docopt::new(USAGE)
        .and_then(|d| d.parse())
        .unwrap_or_else(|e| e.exit());
    let output = args.get_str("--output").to_string();
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(args.get_str("--key"), SslFiletype::PEM)
        .expect("Invalid ssl private key! Please use PEM format");
    builder
        .set_certificate_chain_file(args.get_str("--cert"))
        .expect("Invalid ssl certificate! Please use PEM format");

    server::new(move || {
        // Without this clone it fails miserably in nested closures
        let output = output.clone();
        App::new()
            .resource("/sink/", move |r| {
                r.f(move |req| {
                    info!("Somone hit sink!");

                    // Create a stream with given options
                    let stream: Box<dyn io::Write> = if output.clone() == "-" {
                        Box::new(io::stdout())
                    } else {
                        // Try to open a file, or fallback to stdout.
                        match OpenOptions::new()
                            .write(true)
                            .create(true)
                            .append(true)
                            .open(output.clone())
                        {
                            Ok(file) => Box::new(file),
                            Err(e) => {
                                eprintln!("Unable to open file for writing: {}...", e);
                                Box::new(io::stdout())
                            }
                        }
                    };
                    ws::start(req, Ws::new(stream))
                })
            })
            .finish()
    })
    .bind_ssl(args.get_str("--bind"), builder)
    .unwrap_or_else(|_| panic!("Unable to bind to {}", args.get_str("--bind")))
    .run();
}
