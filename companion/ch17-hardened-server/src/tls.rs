use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

pub fn create_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or("no private key found")?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}
