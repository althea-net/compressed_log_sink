#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate env_logger;
use actix_web::error::InternalError;
use actix_web::middleware::NormalizePath;
use actix_web::post;
use actix_web::web::{JsonConfig, PayloadConfig};
use actix_web::HttpServer;
use actix_web::{web::Json, Responder};
use actix_web::{App, HttpResponse};
use flate2::read::ZlibDecoder;
use rustls::ServerConfig;
use serde_json::Error as SerdeError;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;
use std::time::Duration;
use std::{fs, thread};
use std::{fs::OpenOptions, io::BufReader};

lazy_static! {
    /// This log buffer allows us to maintain a steady stream of logs into the logging server
    /// rather than paying for the connection overhead and write out time for every connection
    /// potentially causing the writer on the other end to time out or generally have issues
    static ref LOG_BUFFER: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));
}

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
    LOG_BUFFER.write().unwrap().extend(logs);
    HttpResponse::Ok().finish()
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
                Ok(pl) => {
                    info!("Got {} lines", pl.logs.len());
                    LOG_BUFFER.write().unwrap().extend(pl.logs);
                    HttpResponse::Ok().finish()
                }
                Err(e) => {
                    error!("Failed to extract logs {:?}", e);
                    HttpResponse::BadRequest().json("Failed to decompress!")
                }
            }
        }
        Err(e) => {
            error!("Failed to decompress logs {:?}", e);
            HttpResponse::BadRequest().json("Failed to decompress!")
        }
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
fn output_logs(logs: Vec<String>) {
    let destination = get_destination_details();
    match destination {
        DestinationType::StdOut => {
            for log in logs {
                println!("{}", log);
            }
        }
        DestinationType::File { path } => {
            let bytes = log_to_bytes(logs);
            info!("Dumping {} bytes of logs to {}", bytes.len(), path);
            let mut options = OpenOptions::new();
            let mut file = options
                .append(true)
                .open(path.clone())
                .expect("Failed to open file for append");
            if let Err(e) = file.write(&bytes) {
                error!("Failed to write to file {:?} with {:?}", path, e);
            }
        }
        DestinationType::TCPStream { url } => {
            let bytes = log_to_bytes(logs);
            let socket: SocketAddr = url.parse().expect("Invalid tcp sink socket");
            info!("Dumping {} bytes of logs to {}", bytes.len(), url);

            let stream = TcpStream::connect(&socket);

            match stream {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(&bytes) {
                        error!("Failed to socket{:?} with {:?}", socket, e);
                    }
                }
                Err(e) => {
                    error!("Failed to connect to socket {:?} with {:?}", socket, e);
                }
            }
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

    let cert_chain = load_certs(&ARGS.flag_cert);
    let keys = load_private_key(&ARGS.flag_key);
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys)
        .unwrap();

    let json_cfg = JsonConfig::default()
        // limit request payload size
        .limit(2usize.pow(32))
        // only accept text/plain content type
        .content_type(|mime| mime == mime::TEXT_PLAIN || mime == mime::APPLICATION_JSON)
        // use custom error handler
        .error_handler(|err, req| {
            info!("Json decoding Err is {:?} req is {:?}", err, req);
            InternalError::from_response(err, HttpResponse::Conflict().into()).into()
        });
    let payload_cfg = PayloadConfig::default().limit(2usize.pow(25));

    // this thread buffers logging output and aggregates into a single tcpstream on the
    // output end, reducing load and load variability on the logging server
    thread::spawn(move || loop {
        let mut logs = LOG_BUFFER.write().unwrap();
        let out_logs = logs.clone();
        logs.clear();
        drop(logs);
        if !out_logs.is_empty() {
            output_logs(out_logs);
        }
        sleep(Duration::from_secs(5));
    });

    HttpServer::new(move || {
        App::new()
            .wrap(NormalizePath::default())
            .service(handle_log_payload)
            .service(handle_compressed_log_payload)
            .app_data(json_cfg.clone())
            .app_data(payload_cfg.clone())
    })
    .bind_rustls(&ARGS.flag_bind, config)?
    .workers(32)
    .run()
    .await?;
    Ok(())
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}
