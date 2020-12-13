extern crate pnet;

use crate::packet::Packet;
use pnet::datalink::dummy;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};

use std::sync::mpsc;

fn create_conn(intf: &str) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == intf;
    let interfaces = datalink::interfaces();
    println!("{:?}", interfaces);
    let interface = interfaces
        .clone()
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    (tx, rx)
}

fn send_packet(tx: &mut Box<dyn DataLinkSender + 'static>, pkt: &Packet) {
    tx.send_to(pkt.as_slice(), None);
    println!("Sent");
}

fn verify_packet(rx: &mut Box<dyn DataLinkReceiver + 'static>, pkt: &Packet) {
    println!("Rx");
    match rx.next() {
        Ok(packet) => {
            println!("{:?}", packet);
            assert!(pkt.compare_with_slice(packet));
        }
        Err(e) => {
            // If an error occurs, we can handle it here
            panic!("An error occurred while reading: {}", e);
        }
    }
}

fn create_mpsc_conn(intf: u8) -> (mpsc::Sender<Packet>, mpsc::Receiver<Packet>) {
    // Create a new channel, dealing with layer 2 packets
    let (mut tx, mut rx) = mpsc::channel();
    (tx, rx)
}

#[test]
fn test_send_packet() {
    let pkt = crate::create_tcp_packet(
        "01:02:03:04:05:01",
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

    let (mut tx, mut rx) = create_conn("lo0");
    // let (_, mut rx) = create_dummy_conn(1);
    send_packet(&mut tx, &pkt);
    verify_packet(&mut rx, &pkt);
}
