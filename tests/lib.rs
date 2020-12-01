#[macro_use]
extern crate rscapy;

use rscapy::headers::*;

#[test]
fn custom_header_test() {
    make_header!(
    MyOwnHeader 10
    (
        bytes_1: 7: 0,
        bytes_2: 23: 8,
        bytes_3: 47: 32,
        bytes_4: 79: 48
    )
    );
    let data: Vec<u8> = (0..10 as u8).map(|x| x).collect();
    let mut my_header = MyOwnHeader(data);
    my_header.bytes();
    my_header.show();

    my_header.set_bytes_1(0x22);
    assert_eq!(0x22, my_header.bytes_1());


    my_header.set_bytes_2(0x3344);
    assert_eq!(0x3344, my_header.bytes_2());
    my_header.show();
}

#[test]
fn inbuilt_header_test() {
    let data = [
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x81, 0x00,
    ];
    let ethernet = Ethernet(data);
    ethernet.bytes();
    ethernet.show();

    let data = [0x00, 0x0a, 0x08, 0x00];
    let vlan = Vlan(data);
    vlan.bytes();
    vlan.show();

    let data = [
        0x45, 0x00, 0x00, 0x14, 0x00, 0x33, 0x40, 0xdd, 0x40, 0x06, 0xfa, 0xec, 0xa, 0xa, 0xa, 0x1,
        0xb, 0xb, 0xb, 0x1,
    ];
    let ipv4 = IPv4(data);
    ipv4.bytes();
    ipv4.show();

    let data: Vec<u8> = (0..40 as u8).map(|x| x).collect();
    let ipv6 = IPv6(data);
    ipv6.bytes();
    ipv6.show();

    let mut v: Vec<u8> = Vec::new();
    v.append(&mut ethernet.octets());
    v.append(&mut vlan.octets());
    v.append(&mut ipv4.octets());
    println!("{:02x?}", v);
}