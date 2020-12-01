extern crate pnet;

use crate::packet::Packet;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

fn send_packet(pkt: &Packet) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == "lo0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    println!("{}", interface);
    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    tx.send_to(pkt.as_slice(), None);
}

fn verify_packet(pkt: &Packet) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == "lo0";
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    println!("{}", interface);
    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    match rx.next() {
        Ok(packet) => {
            assert!(pkt.compare_with_slice(packet));
        }
        Err(e) => {
            // If an error occurs, we can handle it here
            panic!("An error occurred while reading: {}", e);
        }
    }
}
#[test]
fn test_send_packet() {
    let pkt = crate::create_tcp_packet(
        "00:77:66:55:44:33",
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
        8888,
        9090,
        100,
        101,
        5,
        0,
        2,
        0,
        0,
        false,
        100,
    );
    send_packet(&pkt);
    verify_packet(&pkt);
}
