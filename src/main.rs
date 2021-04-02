mod client;
mod pool;
mod server;
extern crate num_cpus;

fn main() {
    let mut socket = client::TCPSocketClient::init();
    let mut pool = pool::Pool::new(num_cpus::get());
    loop {
        client::grab_multiple(&mut pool, &mut socket);
    }
}
