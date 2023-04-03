#[macro_use]
extern crate packet_rs;

use packet_rs::headers::*;
use packet_rs::utils;
use packet_rs::Packet;

fn main() {
    make_header!(
    MyHeader 4
    (
        field_1: 0-2,
        field_2: 3-3,
        field_3: 4-15,
        field_4: 16-31
    )
    vec![0x0, 0xa, 0x8, 0x0]      // <= optional default data
    );

    // 2 ways to use a header
    // Call new on the *MyHeader* header
    let hdr = MyHeader::new();
    hdr.show();

    // Pass a data buffer as an argument
    let mut hdr = MyHeader::from(vec![0xF3, 0x01, 0x08, 0xFF]);
    // fetch the field_2 value
    println!("{}", hdr.field_2());
    // set the field_2 value
    hdr.set_field_2(1);
    hdr.show();

    // create a simple Ether header
    let mut eth = Ether::new();
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
    pkt.push(Ether::new());
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
    let pkt = utils::create_tcp_packet(
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
