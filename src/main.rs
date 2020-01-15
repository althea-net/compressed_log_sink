#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate env_logger;
use actix_web::http::Method;
use actix_web::Error;
use actix_web::{server, App, HttpResponse, Json};
use flate2::read::ZlibDecoder;
use futures::future;
use futures::Future;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde_json;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use tokio::io::write_all;
use tokio::net::TcpStream;
use serde_json::Error as SerdeError;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PlaintextLogs {
    logs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct CompressedLogs {
    compressed_plaintext_logs: Vec<u8>,
}

/// Handler for requests
fn handle_log_payload(
    value: Json<PlaintextLogs>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let logs = value.into_inner().logs;
    output_logs(logs)
}

/// Handler for requests
fn handle_compressed_log_payload(
    value: Json<CompressedLogs>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let bytes = value.into_inner().compressed_plaintext_logs;
    let mut decoder = ZlibDecoder::new(&bytes[..]);
    let mut ret = Vec::new();
    // Extract data from decoder
    let res = io::copy(&mut decoder, &mut ret);
    match res {
        Ok(_) => {
            let plaintext_logs: Result<PlaintextLogs, SerdeError> =
                serde_json::from_slice(&ret);
            match plaintext_logs {
                Ok(pl) => output_logs(pl.logs),
                Err(e) => {Box::new(future::err(e.into()))}
            }
        }
        Err(e) => {Box::new(future::err(e.into()))}
    }
}

/// Enum of possible log output destinations
pub enum DestinationType {
    StdOut,
    TCPStream { url: String },
    File { path: String },
}

/// Helper function for converting the destination argument string into a DestinationType enum
/// value
fn get_destination_details() -> DestinationType {
    match ARGS.flag_output.clone() {
        Some(destination) => {
            if destination.contains(":") && !destination.starts_with("/") {
                DestinationType::TCPStream { url: destination }
            } else if destination == "-" {
                DestinationType::StdOut
            } else {
                DestinationType::File { path: destination }
            }
        }
        None => DestinationType::StdOut,
    }
}

/// Dumb helper function to make sure the file exists so that we don't have to check
/// for that before appending to it later on
fn create_output_file() {
    if let DestinationType::File { path } = get_destination_details() {
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
            .expect(&format!("Failed to create output file! {}", path));
    }
}

/// Dumb helper function to make sure the tcp socket arg is valid
fn check_tcp_arg() {
    if let DestinationType::TCPStream { url } = get_destination_details() {
        let _s: SocketAddr = url
            .parse()
            .expect(&format!("{} is not a valid SocketAddr", url));
    }
}

fn log_to_bytes(logs: Vec<String>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for log in logs {
        bytes.extend(log.into_bytes());
    }
    bytes
}

/// Takes the raw log lines from log input handlers and puts them out on the correct output
/// The options for output are either - for stdout, a file path, or a url for direct tcp log dump
fn output_logs(logs: Vec<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let destination = get_destination_details();
    match destination {
        DestinationType::StdOut => {
            for log in logs {
                println!("{}", log);
            }
            Box::new(future::ok(HttpResponse::Ok().json(())))
        }
        DestinationType::File { path } => {
            let bytes = log_to_bytes(logs);
            info!("Dumping {} bytes of logs to {}", bytes.len(), path);
            let mut options = OpenOptions::new();
            let mut file = options
                .append(true)
                .open(path)
                .expect("Failed to open file for append");
            let res = file.write(&bytes);
            if res.is_err() {
                return Box::new(future::ok(HttpResponse::InternalServerError().json(())));
            }
            Box::new(future::ok(HttpResponse::Ok().json(())))
        }
        DestinationType::TCPStream { url } => {
            let bytes = log_to_bytes(logs);
            let socket: SocketAddr = url.parse().expect("Invalid tcp sink socket");
            info!("Dumping {} bytes of logs to {}", bytes.len(), url);
            Box::new(
                TcpStream::connect(&socket)
                    .from_err()
                    .and_then(move |stream| {
                        write_all(stream, bytes)
                            .from_err()
                            .and_then(|_res| Ok(HttpResponse::Ok().json(())))
                    }),
            )
        }
    }
}

use docopt::Docopt;

#[derive(Debug, Deserialize, Default)]
pub struct Args {
    flag_bind: String,
    flag_cert: String,
    flag_key: String,
    flag_output: Option<String>,
}

lazy_static! {
    pub static ref ARGS: Args = Docopt::new((*USAGE).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
}

lazy_static! {
    static ref USAGE: String = format!(
        "
Compressed log sink.

Usage:
  compressed_log_sink --bind=<address> --cert=<cert-path> --key=<key-path> [ --output=<stream> ]
  compressed_log_sink (-h | --help)
  compressed_log_sink --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --bind=<address>  Bind to address [default: 0.0.0.0:9999].
  --output=<stream>  Output stream [default: stdout].
  --cert=<path>     Https certificate chain.
  --key=<path>     Https keyfile.
About:
    Version {}",
        env!("CARGO_PKG_VERSION"),
    );
}

fn main() {
    env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();
    info!("Compressed log sink starting!");
    create_output_file();
    check_tcp_arg();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(&ARGS.flag_key, SslFiletype::PEM)
        .expect("Invalid ssl private key! Please use PEM format");
    builder
        .set_certificate_chain_file(&ARGS.flag_cert)
        .expect("Invalid ssl certificate! Please use PEM format");

    server::new(move || {
        App::new()
            .route("/sink", Method::POST, handle_log_payload)
            .route("/sink", Method::POST, handle_log_payload)
            .route(
                "/compressed_sink",
                Method::POST,
                handle_compressed_log_payload,
            )
            .route(
                "/compressed_sink/",
                Method::POST,
                handle_compressed_log_payload,
            )
            .finish()
    })
    .bind_ssl(&ARGS.flag_bind, builder)
    .unwrap_or_else(|_| panic!("Unable to bind to {}", ARGS.flag_bind))
    .workers(4)
    .run();
}
