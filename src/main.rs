mod client;
mod pool;
mod server;
extern crate num_cpus;

fn main() {
    let mut socket = client::TLSSocketClient::init();
    loop {
        client::grab_multiple(num_cpus::get(), &mut socket);
    }
}
