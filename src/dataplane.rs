extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};

use std::env;

fn send_packet() {
    let interface_names_match = |iface: &NetworkInterface| iface.name == "lo0";
    let interfaces = datalink::interfaces();
    println!("{:?}", interfaces);
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
                let packet = EthernetPacket::new(packet).unwrap();

                // Constructs a single packet, the same length as the the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
                tx.build_and_send(1, packet.packet().len(),
                    &mut |mut new_packet| {
                        let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                        // Create a clone of the original packet
                        new_packet.clone_from(&packet);

                        // Switch the source and destination
                        new_packet.set_source(packet.get_destination());
                        new_packet.set_destination(packet.get_source());
                });
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
}

#[test]
fn test_send_packet() {
    send_packet();
}
