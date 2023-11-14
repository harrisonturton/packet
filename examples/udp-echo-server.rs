use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    println!("Running on port 2000");
    println!("Try connecting with nc -u 127.0.0.1 2000");

    let socket = UdpSocket::bind("0.0.0.0:2000")?;
    let mut buf = [0; 2048];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        let buf = &mut buf[..amt];
        print!("{}", String::from_utf8_lossy(buf));
        socket.send_to(buf, &src)?;
    }
}
