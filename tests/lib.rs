#[macro_use]
extern crate packet_rs;

use packet_rs::headers::*;
use packet_rs::utils;

use std::time::Instant;

mod pcap;

const UDP_PORT_VXLAN: u16 = 4789;

pub fn ipv4_checksum_verify(v: &[u8]) -> u16 {
    let mut chksum: u32 = 0;
    for i in (0..v.len()).step_by(2) {
        let msb: u16 = (v[i] as u16) << 8;
        chksum += msb as u32 | v[i + 1] as u32;
    }
    while chksum >> 16 != 0 {
        chksum = (chksum >> 16) + chksum & 0xFFFF;
    }
    let out = !(chksum as u16);
    out
}

#[cfg(test)]
mod tests {

    use super::*;
    use packet_rs::parser;
    use packet_rs::Packet;
    use pcap::pcap_write;

    #[test]
    fn custom_header_test() {
        make_header!(
        MyOwnHeader 10
        (
            bytes_1: 0-7,
            bytes_2: 8-23,
            bytes_3: 32-47,
            bytes_4: 48-79
        )
        );
        let data: Vec<u8> = vec![0; 10];
        let mut my_header = MyOwnHeader::from(data);
        my_header.to_vec().as_slice();
        my_header.show();

        my_header.set_bytes_1(0x22);
        assert_eq!(0x22, my_header.bytes_1());

        my_header.set_bytes_2(0x3344);
        assert_eq!(0x3344, my_header.bytes_2());
        my_header.show();
    }
    #[test]
    fn ethernet_header_test() {
        let mut eth = Ether::new();
        eth.show();

        // dst
        assert_eq!(0x102030405, eth.dst());
        eth.set_dst(0x60708090a0b as u64);
        assert_eq!(0x60708090a0b, eth.dst());

        // src
        assert_eq!(0x60708090a0b, eth.src());
        eth.set_src(0x102030405 as u64);
        assert_eq!(0x102030405, eth.src());

        // etype
        assert_eq!(0x800, eth.etype());
        eth.set_etype(0x8100 as u64);
        assert_eq!(0x8100, eth.etype());

        let a = [
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x86, 0xdd,
        ];
        let eth = Ether::from(a.to_vec());
        let t = eth.to_vec();
        let b = t.as_slice();
        assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 14);
        assert_eq!(0xaaaaaaaaaaaa, eth.dst());
        assert_eq!(0xbbbbbbbbbbbb, eth.src());
        assert_eq!(0x86dd, eth.etype());
    }
    #[test]
    fn vlan_header_test() {
        let mut vlan = Vlan::new();
        vlan.show();

        // pcp
        assert_eq!(vlan.pcp(), 0x0);
        vlan.set_pcp(0x5 as u64);
        assert_eq!(vlan.pcp(), 0x5);

        // cfi
        assert_eq!(vlan.cfi(), 0x0);
        vlan.set_cfi(0x1 as u64);
        assert_eq!(vlan.cfi(), 0x1);

        // vid
        assert_eq!(vlan.vid(), 0xa);
        vlan.set_vid(0xb as u64);
        assert_eq!(vlan.vid(), 0xb);

        let a = [0x7f, 0xff, 0x08, 0x00];
        let vlan = Vlan::from(a.to_vec());
        let t = vlan.to_vec();
        let b = t.as_slice();
        assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 4);
        assert_eq!(vlan.vid(), 4095);
        assert_eq!(vlan.pcp(), 3);
        assert_eq!(vlan.cfi(), 1);
    }
    #[test]
    fn ip_header_test() {
        let ipv4 = IPv4::new();
        ipv4.to_vec().as_slice();
        ipv4.show();

        let data = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x33, 0x40, 0xdd, 0x40, 0x06, 0xfa, 0xec, 0xa, 0xa, 0xa,
            0x1, 0xb, 0xb, 0xb, 0x1,
        ];
        let ipv4 = IPv4::from(data.to_vec());
        ipv4.show();

        let ipv4 = Packet::ipv4(5, 10, 4, 64, 0xdd, 6, "10.10.10.1", "11.11.11.1", 86);
        assert_eq!(ipv4_checksum_verify(ipv4.to_vec().as_slice()), 0);

        let data: Vec<u8> = vec![0; IPv6::size()];
        let ipv6 = IPv6::from(data);
        ipv6.to_vec().as_slice();
        ipv6.show();
    }
    #[test]
    fn vxlan_header_test() {
        let vxlan = Vxlan::new();
        vxlan.show();
        assert_eq!(vxlan.flags(), 0x8);
        assert_eq!(vxlan.vni(), 2000);

        let vxlan1 = Packet::vxlan(2000);
        vxlan1.show();
        assert_eq!(vxlan1.flags(), 0x8);
        assert_eq!(vxlan1.vni(), 2000);
    }
    #[test]
    fn ip_checksum_test() {
        let payload: Vec<u8> = (0..100).collect::<Vec<u8>>();
        let ips = vec![
            "10.10.10.1",
            "11.11.11.1",
            "12.12.12.1",
            "13.13.13.1",
            "14.14.14.1",
            "15.15.15.1",
            "16.16.16.1",
            "17.17.17.1",
            "18.18.18.1",
            "19.19.19.1",
        ];
        for sip in &ips {
            for dip in &ips {
                for ttl in 1..255 {
                    let pkt = utils::create_tcp_packet(
                        "00:01:02:03:04:05",
                        "00:06:07:08:09:0a",
                        false,
                        10,
                        3,
                        5,
                        sip,
                        dip,
                        0,
                        ttl,
                        115,
                        0,
                        Vec::new(),
                        80,
                        9090,
                        100,
                        101,
                        0,
                        0,
                        1,
                        0,
                        0,
                        false,
                        &payload,
                    );
                    let ip: &IPv4 = (&pkt["IPv4"]).into();
                    assert_eq!(ipv4_checksum_verify(ip.to_vec().as_slice()), 0);

                    let ipv4 = Packet::ipv4(5, 0, 115, ttl, 0, 6, sip, dip, 140);
                    assert_eq!(ipv4_checksum_verify(ipv4.to_vec().as_slice()), 0);

                    assert_eq!(ip.header_checksum(), ipv4.header_checksum());
                }
            }
        }
    }
    #[test]
    fn arp_header_test() {
        let arp = ARP::new();
        arp.show();
        assert_eq!(arp.hwtype(), 0x1);
        assert_eq!(arp.proto_type(), 0x800);
        assert_eq!(arp.hwlen(), 0x6);
        assert_eq!(arp.proto_len(), 0x4);
        assert_eq!(arp.opcode(), 1);
        assert_eq!(arp.sender_hw_addr(), 0x000102030405);
        assert_eq!(arp.sender_proto_addr(), 0xa000001);
        assert_eq!(arp.target_hw_addr(), 0x0000000000);
        assert_eq!(arp.target_proto_addr(), 0x0);
    }
    #[test]
    fn create_packet_test() {
        let payload: Vec<u8> = (0..100).collect::<Vec<u8>>();
        let _tcp = utils::create_tcp_packet(
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
            &payload,
        );

        let _udp = utils::create_udp_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            1234,
            9090,
            false,
            &payload,
        );

        let _icmp = utils::create_icmp_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            8,
            0,
            Vec::new(),
            false,
            &payload,
        );

        let _tcpv6 = utils::create_tcpv6_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            1234,
            9090,
            100,
            101,
            5,
            0,
            1,
            0,
            0,
            &payload,
        );

        let _udpv6 = utils::create_udpv6_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            1234,
            9090,
            false,
            &payload,
        );

        let _icmpv6 = utils::create_icmpv6_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            135,
            0,
            Vec::new(),
            false,
            &payload,
        );

        let _vxlan_udp = utils::create_vxlan_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            UDP_PORT_VXLAN,
            9090,
            false,
            2000,
            _udp.clone(),
        );

        let _vxlan_tcp = utils::create_vxlan_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            UDP_PORT_VXLAN,
            9090,
            false,
            2000,
            _tcp.clone(),
        );

        let _vxlanv6_udp = utils::create_vxlanv6_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            UDP_PORT_VXLAN,
            9090,
            false,
            2000,
            _udp.clone(),
        );

        let _vxlanv6_tcp = utils::create_vxlanv6_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            UDP_PORT_VXLAN,
            9090,
            false,
            2000,
            _tcp.clone(),
        );

        let _arp_req = utils::create_arp_packet(
            "FF:FF:FF:FF:FF:FF",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            1,
            "00:06:07:08:09:0a",
            "00:00:00:00:00:00",
            "10.10.10.1",
            "0.0.0.0",
            &payload,
        );

        let _arp_resp = utils::create_arp_packet(
            "00:06:07:08:09:0a",
            "00:01:02:03:04:05",
            false,
            10,
            3,
            2,
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            "10.10.10.2",
            "10.10.10.1",
            &payload,
        );

        let mut ip_tcp = _tcp.clone();
        ip_tcp.remove(0);
        let mut ip_udp = _udp.clone();
        ip_udp.remove(0);
        let mut ip_tcpv6 = _tcpv6.clone();
        ip_tcpv6.remove(0);
        let mut ip_udpv6 = _udpv6.clone();
        ip_udpv6.remove(0);

        let _ip4ip4 = utils::create_ipv4ip_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            ip_tcp.clone(),
        );

        let _ip4ip6 = utils::create_ipv4ip_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            ip_udpv6.clone(),
        );

        let _ip6ip4 = utils::create_ipv6ip_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            ip_udp.clone(),
        );

        let _ip6ip6 = utils::create_ipv6ip_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            4,
            64,
            "AAAA::1",
            "BBBB::1",
            ip_tcpv6.clone(),
        );

        let _greip4 = utils::create_gre_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            false,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            &[],
            Some(ip_tcp.clone()),
        );

        let _greip6 = utils::create_gre_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            false,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            &[],
            Some(ip_udpv6.clone()),
        );

        let _erspan2 = utils::create_erspan_2_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            23,
            0,
            0,
            1,
            0,
            10,
            10,
            Some(_udpv6.clone()),
        );

        let _erspan3 = utils::create_erspan_3_packet(
            "00:01:02:03:04:05",
            "00:06:07:08:09:0a",
            false,
            10,
            3,
            5,
            "192.168.0.199",
            "192.168.0.1",
            0,
            64,
            0,
            0x4000,
            Vec::new(),
            23,
            0,
            0,
            1,
            0,
            10,
            10,
            10,
            1,
            4,
            0xffffffff,
            Some(_icmp.clone()),
        );

        let mut _llc = Packet::new();
        _llc.push(Dot3::from(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x0, 86,
        ]));
        _llc.push(LLC::from(vec![0x0, 0x04, 0x0]));

        let mut _snap = Packet::new();
        _snap.push(Dot3::from(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x0, 86,
        ]));
        _snap.push(LLC::from(vec![0xaa, 0xaa, 0x03]));
        _snap.push(SNAP::from(vec![0x0, 0x80, 0xc2, 0x8, 0x0]));

        let pkts: Vec<&Packet> = vec![
            &_tcp,
            &_udp,
            &_icmp,
            &_tcpv6,
            &_udpv6,
            &_icmpv6,
            &_vxlan_udp,
            &_vxlanv6_udp,
            &_vxlan_tcp,
            &_vxlanv6_tcp,
            &_arp_req,
            &_arp_resp,
            &_ip4ip4,
            &_ip4ip6,
            &_ip6ip4,
            &_ip6ip6,
            &_llc,
            &_snap,
            &_greip4,
            &_greip6,
            &_erspan2,
            &_erspan3,
        ];
        pcap_write(&pkts.iter().map(|x| x.to_vec() as Vec<u8>).collect());

        for pkt in pkts {
            let parsed = parser::slow::parse(pkt.to_vec().as_slice());
            // parsed.show();
            // pkt.show();
            assert!(parsed.compare(&pkt));
        }
    }

    fn test_tcp_packet_with_payload(payload: &[u8]) -> Packet {
        utils::create_tcp_packet(
            "00:11:11:11:11:11",
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
            payload,
        )
    }

    fn test_tcp_packet() -> Packet {
        let payload: Vec<u8> = (0..100).collect::<Vec<u8>>();
        test_tcp_packet_with_payload(&payload)
    }

    #[test]
    fn update_packet_test() {
        let mut pkt = test_tcp_packet();
        pkt.show();
        let x: &mut Box<dyn Header> = &mut pkt["Ether"];
        let x: &mut Ether = x.into();
        x.set_etype(0x86dd);
        x.show();

        let new_pkt = pkt.clone();
        new_pkt.show();
        pkt.show();
        assert_eq!(true, pkt.compare(&new_pkt));
        assert_eq!(true, pkt.compare_with_slice(new_pkt.to_vec().as_slice()));

        // immutable
        let x: &Ether = pkt.get_header("Ether").unwrap();
        println!("{}", x.etype());
        x.show();

        let y: &Box<dyn Header> = &pkt["Ether"];
        let x: &Ether = y.into();
        println!("{}", x.etype());
        x.show();

        let x: &Ether = (&pkt["Ether"]).into();
        println!("{}", x.etype());
        x.show();

        // mutable
        let x: &mut Ether = pkt.get_header_mut("Ether").unwrap();
        x.set_etype(0x9999);
        x.show();

        let x: &mut Box<dyn Header> = &mut pkt["Ether"];
        let x: &mut Ether = x.into();
        x.set_etype(0x9999);
        x.show();
    }
    #[test]
    fn pktgen_perf_test() {
        let cnt = 300000;
        let mut pkt = test_tcp_packet();

        // new packet in every iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let p = test_tcp_packet();
            p.to_vec();
            // p.show();
        }
        println!("New {} packets          : {:?}", cnt, start.elapsed());

        // clone packet in each iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let p = pkt.clone();
            p.to_vec();
            // p.show();
        }
        println!("Clone {} packets        : {:?}", cnt, start.elapsed());

        // update packet and then clone in each iteration
        let start = Instant::now();
        for i in 0..cnt {
            let x: &mut Ether = (&mut pkt["Ether"]).into();
            x.set_etype(i % 0xFFFF);
            let p = pkt.clone();
            p.to_vec();
            // p.show();
        }
        println!("Update+Clone {} packets : {:?}", cnt, start.elapsed());
    }
    #[test]
    fn parse_test() {
        let cnt = 300000;
        let pkt = test_tcp_packet().to_vec();

        let slice = pkt.as_slice();
        // parse in every iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let p = parser::slow::parse(&slice);
            p.to_vec();
        }
        println!("{} packets parsed   : {:?}", cnt, start.elapsed());
    }
    #[test]
    fn parse_slice_test() {
        let cnt = 300000;
        let pkt = test_tcp_packet().to_vec();

        let slice = pkt.as_slice();

        // parse in every iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let p = parser::fast::parse(&slice);
            p.to_vec();
        }
        println!("{} packets parsed   : {:?}", cnt, start.elapsed());
    }
    #[test]
    fn packet_slice_payload_test() {
        let payload: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pkt = test_tcp_packet_with_payload(payload).to_vec();

        let slice = pkt.as_slice();

        let p = parser::fast::parse(&slice);
        assert_eq!(p.payload(), payload);
    }
    #[test]
    fn packet_payload_test() {
        let payload: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pkt = test_tcp_packet_with_payload(payload).to_vec();

        let slice = pkt.as_slice();

        let p = parser::slow::parse(&slice);
        assert_eq!(p.payload(), payload);
    }
}
