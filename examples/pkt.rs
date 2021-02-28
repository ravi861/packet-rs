extern crate rpacket;

use rpacket::headers::*;
use rpacket::Packet;

fn main() {
    // create a simple Ethernet header
    let mut eth = Ethernet::new();
    eth.show();

    // get the etype field from the header
    let etype = eth.etype();
    println!("{}", etype);

    // update the etype field in the header
    eth.set_etype(0x8100);
    eth.show();

    // use the Packet associate function to create ethernet header
    let eth = Packet::ethernet("00:11:11:11:11:11", "00:11:11:11:11:11", 0x8100);
    eth.show();

    // create a UDP packet by pushing each header in sequence
    let mut pkt = Packet::new(100);
    pkt.push(Ethernet::new());
    pkt.push(IPv4::new());
    pkt.push(UDP::new());
    pkt.show();

    // convert packet to byte array
    let v = pkt.to_vec();
    println!("{:?}", v);

    // duplicate a packet using clone
    let new_pkt = pkt.clone();
    new_pkt.show();

    // create a TCP packet using the Packet associate function
    let pkt = Packet::create_tcp_packet(
        "00:01:02:03:04:05",
        "00:06:07:08:09:0a",
        false,
        10,
        3,
        5,
        "10.10.10.1",
        "11.11.11.1",
        0,
        64,
        115,
        0,
        Vec::new(),
        1234,
        9090,
        100,
        101,
        5,
        0,
        0x10,
        2,
        0,
        false,
        100,
    );
    pkt.show();
}
