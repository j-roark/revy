mod client;
mod pool;
use std::env;
extern crate num_cpus;

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let mut socket = client::build_socket(&mut args);
    let mut pool = pool::Pool::new(num_cpus::get());
    match socket.is_ssl() {
        true => {
            let mut ssl_socket = socket.pop_tls();
            println!("Alive and running on an encrypted stream.");
            loop {
                client::grab_multiple(&mut pool, &mut ssl_socket)
            }
        }
        false => {
            let mut nossl_socket = socket.pop_tcp();
            println!("Alive and running on an unencrypted stream.");
            loop {
                client::grab_multiple(&mut pool, &mut nossl_socket)
            }
        }
    }
}
