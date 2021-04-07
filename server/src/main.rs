mod pool;
mod server;
extern crate num_cpus;

fn main() {
    let server_config = server::ServerConfig {
        socket_type: Some(server::SocketType::NoTls),
        pool_size: Some(12 as usize),
        frame_time: None,
        compression_quality: Some(server::CompressionQuality::Best)
    };
    let mut server = server::TCPSocketServer::init(server_config);
    loop {
        server.run();
    }
}

