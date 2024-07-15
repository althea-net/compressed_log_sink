#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate env_logger;
use actix_web::error::InternalError;
use actix_web::middleware::NormalizePath;
use actix_web::web::{JsonConfig, PayloadConfig};
use actix_web::HttpServer;
use actix_web::{post, web};
use actix_web::{web::Json, Responder};
use actix_web::{App, HttpResponse};
use crossbeam::queue::SegQueue;
use flate2::read::ZlibDecoder;
use rustls::ServerConfig;
use serde_json::Error as SerdeError;
use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{fs, thread};
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
async fn handle_log_payload(
    value: Json<PlaintextLogs>,
    data: web::Data<(Args, Arc<SegQueue<String>>)>,
) -> impl Responder {
    let logs = value.into_inner().logs;
    for log in &logs {
        data.1.push(log.clone());
    }
    HttpResponse::Ok().finish()
}

/// Handler for requests
#[post("/compressed_sink")]
async fn handle_compressed_log_payload(
    request: Json<CompressedLogs>,
    data: web::Data<(Args, Arc<SegQueue<String>>)>,
) -> impl Responder {
    let bytes = request.into_inner().compressed_plaintext_logs;
    let mut decoder = ZlibDecoder::new(&bytes[..]);
    let mut ret = Vec::new();
    // Extract data from decoder
    let res = io::copy(&mut decoder, &mut ret);
    match res {
        Ok(_) => {
            let plaintext_logs: Result<PlaintextLogs, SerdeError> = serde_json::from_slice(&ret);
            match plaintext_logs {
                Ok(mut pl) => {
                    info!("Got {} lines", pl.logs.len());

                    if data.0.flag_deupe {
                        // filter all duplicate lines
                        let set: HashSet<_> = pl.logs.drain(..).collect();
                        pl.logs.extend(set.into_iter());
                        info!("Filtered down to {} lines", pl.logs.len());
                    }
                    for log in pl.logs {
                        data.1.push(log);
                    }
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
fn get_destination_details(args: Args) -> DestinationType {
    match args.flag_output.clone() {
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
fn create_output_file(args: Args) {
    if let DestinationType::File { path } = get_destination_details(args) {
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
            .unwrap_or_else(|_| panic!("Failed to create output file! {}", path));
    }
}

/// Dumb helper function to make sure the tcp socket arg is valid
fn check_tcp_arg(args: Args) {
    if let DestinationType::TCPStream { url } = get_destination_details(args) {
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
fn output_logs(logs: Vec<String>, args: Args) {
    let destination = get_destination_details(args);
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

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Args {
    flag_bind: String,
    flag_cert: String,
    flag_key: String,
    flag_output: Option<String>,
    flag_deupe: bool,
}

fn get_usage() -> String {
    format!(
        "
Compressed log sink.

Usage:
  compressed_log_sink --bind=<address> --cert=<cert-path> --key=<key-path> --dedupe=<bool> [ --output=<stream> ]
  compressed_log_sink (-h | --help)
  compressed_log_sink --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --bind=<address>  Bind to address [default: 0.0.0.0:9999].
  --output=<stream>  Output stream [default: stdout].
  --cert=<path>     Https certificate chain.
  --key=<path>     Https keyfile.
  --dedupe=<bool>  Remove duplicate lines from logs. True or False.  Default: False
About:
    Version {}",
        env!("CARGO_PKG_VERSION"),
    )
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();

    let args: Args = Docopt::new((get_usage()).as_str())
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    info!("Compressed log sink starting!");
    create_output_file(args.clone());
    check_tcp_arg(args.clone());

    let cert_chain = load_certs(&args.flag_cert);
    let keys = load_private_key(&args.flag_key);
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
    let log_queue: Arc<SegQueue<String>> = Arc::new(SegQueue::new());

    // this thread buffers logging output and aggregates into a single tcpstream on the
    // output end, reducing load and load variability on the logging server
    let alt_queue = log_queue.clone();
    let alt_args = args.clone();
    thread::spawn(move || {
        let log_queue = alt_queue.clone();
        let args = alt_args.clone();
        loop {
            // each batch uses a single tcp connection
            // to send the logs in, we want some batch size
            // to avoid repeating the connection process constantly
            let mut batch = Vec::new();
            const BATCH_SIZE: usize = 100_000;
            while let Some(line) = log_queue.pop() {
                batch.push(line);
                if batch.len() >= BATCH_SIZE {
                    output_logs(batch.clone(), args.clone());
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                output_logs(batch, args.clone());
            }
            sleep(Duration::from_secs(1));
        }
    });

    let shared_data = web::Data::new((args.clone(), log_queue.clone()));

    HttpServer::new(move || {
        App::new()
            .wrap(NormalizePath::new(
                actix_web::middleware::TrailingSlash::Trim,
            ))
            .service(handle_log_payload)
            .service(handle_compressed_log_payload)
            .app_data(json_cfg.clone())
            .app_data(payload_cfg.clone())
            .app_data(shared_data.clone())
    })
    .bind_rustls(&args.flag_bind, config)?
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
