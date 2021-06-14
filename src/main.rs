#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate env_logger;
use actix_web::error::InternalError;
use actix_web::post;
use actix_web::web::JsonConfig;
use actix_web::{web::Json, Responder};
use actix_web::{App, HttpResponse};
use actix_web::{Error, HttpServer};
use flate2::read::ZlibDecoder;
use rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    NoClientAuth, ServerConfig,
};
use serde_json::Error as SerdeError;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::{fs::File, io};
use std::{fs::OpenOptions, io::BufReader};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PlaintextLogs {
    logs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct CompressedLogs {
    compressed_plaintext_logs: Vec<u8>,
}

/// Handler for requests
#[post("/sink")]
async fn handle_log_payload(value: Json<PlaintextLogs>) -> impl Responder {
    let logs = value.into_inner().logs;
    output_logs(logs).await
}

/// Handler for requests
#[post("/compressed_sink")]
async fn handle_compressed_log_payload(request: Json<CompressedLogs>) -> impl Responder {
    let bytes = request.into_inner().compressed_plaintext_logs;
    let mut decoder = ZlibDecoder::new(&bytes[..]);
    let mut ret = Vec::new();
    // Extract data from decoder
    let res = io::copy(&mut decoder, &mut ret);
    match res {
        Ok(_) => {
            let plaintext_logs: Result<PlaintextLogs, SerdeError> = serde_json::from_slice(&ret);
            match plaintext_logs {
                Ok(pl) => output_logs(pl.logs).await,
                Err(e) => {
                    error!("Failed to extract logs {:?}", e);
                    Ok(HttpResponse::BadRequest().json("Failed to decompress!"))
                }
            }
        }
        Err(e) => Err(e.into()),
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
            if destination.contains(':') && !destination.starts_with('/') {
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
            .unwrap_or_else(|_| panic!("Failed to create output file! {}", path));
    }
}

/// Dumb helper function to make sure the tcp socket arg is valid
fn check_tcp_arg() {
    if let DestinationType::TCPStream { url } = get_destination_details() {
        let _s: SocketAddr = url
            .parse()
            .unwrap_or_else(|_| panic!("{} is not a valid SocketAddr", url));
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
async fn output_logs(logs: Vec<String>) -> Result<HttpResponse, Error> {
    let destination = get_destination_details();
    match destination {
        DestinationType::StdOut => {
            for log in logs {
                println!("{}", log);
            }
            Ok(HttpResponse::Ok().json(()))
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
                return Ok(HttpResponse::InternalServerError().json(()));
            }
            Ok(HttpResponse::Ok().json(()))
        }
        DestinationType::TCPStream { url } => {
            let bytes = log_to_bytes(logs);
            let socket: SocketAddr = url.parse().expect("Invalid tcp sink socket");
            info!("Dumping {} bytes of logs to {}", bytes.len(), url);

            let mut stream = TcpStream::connect(&socket)?;
            let _ = stream.write_all(&bytes);
            Ok(HttpResponse::Ok().json(()))
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

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();
    info!("Compressed log sink starting!");
    create_output_file();
    check_tcp_arg();

    let mut config = ServerConfig::new(NoClientAuth::new());
    let cert_file = &mut BufReader::new(
        File::open(&ARGS.flag_cert).expect("Invalid ssl certificate! Please use PEM format"),
    );
    let key_file = &mut BufReader::new(
        File::open(&ARGS.flag_key).expect("Invalid ssl private key! Please use PEM format"),
    );
    let cert_chain = certs(cert_file).unwrap();
    let mut keys = pkcs8_private_keys(key_file).unwrap();
    config.set_single_cert(cert_chain, keys.remove(0)).unwrap();

    let json_cfg = JsonConfig::default()
        // limit request payload size
        .limit(1048576)
        // only accept text/plain content type
        .content_type(|mime| mime == mime::TEXT_PLAIN || mime == mime::APPLICATION_JSON)
        // use custom error handler
        .error_handler(|err, req| {
            info!("Json decoding Err is {:?} req is {:?}", err, req);
            InternalError::from_response(err, HttpResponse::Conflict().into()).into()
        });

    HttpServer::new(move || {
        App::new()
            .service(handle_log_payload)
            .service(handle_compressed_log_payload)
            .app_data(json_cfg.clone())
    })
    .bind_rustls(&ARGS.flag_bind, config)?
    .workers(32)
    .run()
    .await?;
    Ok(())
}
