#[macro_use]
extern crate rscapy;

use rscapy::headers::*;

use std::time::Instant;

mod pcap;

#[cfg(test)]
mod tests {

    use super::*;
    use pcap::pcap_write;
    use rscapy::packet::*;
    use rscapy::Packet;

    #[test]
    fn set_get_octets_test() {
        let mut dips = Vec::new();
        dips.push(String::from("FFFF::FFFF").to_ipv6_bytes());
        dips.push(String::from("7FFF::FFFF").to_ipv6_bytes());
        dips.push(String::from("FFF7::FFFF").to_ipv6_bytes());
        dips.push(String::from("FFFF::FFF7").to_ipv6_bytes());
        dips.push(String::from("FFFF::7FFF").to_ipv6_bytes());
        dips.push(String::from("1111::FFFF").to_ipv6_bytes());
        dips.push(String::from("8888::FFFF").to_ipv6_bytes());
        dips.push(String::from("FFFF::1111").to_ipv6_bytes());
        dips.push(String::from("FFFF::8888").to_ipv6_bytes());
        dips.push(String::from("8888::1111").to_ipv6_bytes());
        dips.push(String::from("2001:3001:4001::FFFF").to_ipv6_bytes());
        dips.push(String::from("FFFF:4001:3001::2001").to_ipv6_bytes());
        dips.push(String::from("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").to_ipv6_bytes());
        dips.push(String::from("1111:1111:1111:1111:1111:1111:1111:1111").to_ipv6_bytes());
        dips.push(String::from("8888:8888:8888:8888:8888:8888:8888:8888").to_ipv6_bytes());
        dips.push(String::from("FFFF:4001:3001:2001:2001:3001:4001:FFFF").to_ipv6_bytes());
        dips.push(String::from("2001:3001:4001:FFFF:FFFF:4001:3001:2001").to_ipv6_bytes());
        let sips = dips.clone();

        let mut ipv6 = IPv6::new();
        for a in dips {
            ipv6.set_bytes(IPv6::dst_msb(), IPv6::dst_lsb(), &a);
            let b = ipv6.bytes(IPv6::dst_msb(), IPv6::dst_lsb());
            let b = b.as_slice();
            assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 16);
        }
        for a in sips {
            ipv6.set_bytes(IPv6::src_msb(), IPv6::src_lsb(), &a);
            let b = ipv6.bytes(IPv6::src_msb(), IPv6::src_lsb());
            let b = b.as_slice();
            assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 16);
        }
    }
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
        my_header.as_slice();
        my_header.show();

        my_header.set_bytes_1(0x22);
        assert_eq!(0x22, my_header.bytes_1());

        my_header.set_bytes_2(0x3344);
        assert_eq!(0x3344, my_header.bytes_2());
        my_header.show();
    }
    #[test]
    fn ethernet_header_test() {
        let mut eth = Ethernet::new();
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
        let eth = Ethernet::from(a.to_vec());
        let b = eth.as_slice();
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
        let b = vlan.as_slice();
        assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 4);
        assert_eq!(vlan.vid(), 4095);
        assert_eq!(vlan.pcp(), 3);
        assert_eq!(vlan.cfi(), 1);
    }
    #[test]
    fn ip_header_test() {
        let ipv4 = IPv4::new();
        ipv4.as_slice();
        ipv4.show();

        let data = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x33, 0x40, 0xdd, 0x40, 0x06, 0xfa, 0xec, 0xa, 0xa, 0xa,
            0x1, 0xb, 0xb, 0xb, 0x1,
        ];
        let ipv4 = IPv4::from(data.to_vec());
        ipv4.show();

        let ipv4 = Packet::ipv4(5, 10, 4, 64, 0xdd, 6, "10.10.10.1", "11.11.11.1", 86);
        assert_eq!(ipv4_checksum_verify(ipv4.as_slice()), 0);

        let data: Vec<u8> = vec![0; IPv6::size()];
        let ipv6 = IPv6::from(data);
        ipv6.as_slice();
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
                    let pkt = Packet::create_tcp_packet(
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
                        100,
                    );
                    let ip: &IPv4 = (&pkt["IPv4"]).into();
                    assert_eq!(ipv4_checksum_verify(ip.as_slice()), 0);

                    let ipv4 = Packet::ipv4(5, 0, 115, ttl, 0, 6, sip, dip, 86);
                    assert_eq!(ipv4_checksum_verify(ipv4.as_slice()), 0);

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
        let _tcp = Packet::create_tcp_packet(
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

        let _udp = Packet::create_udp_packet(
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
            129,
        );

        let _icmp = Packet::create_icmp_packet(
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
            129,
        );

        let _tcpv6 = Packet::create_tcpv6_packet(
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
            100,
        );

        let _udpv6 = Packet::create_udpv6_packet(
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
            129,
        );

        let _icmpv6 = Packet::create_icmpv6_packet(
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
            129,
        );

        let _vxlan_udp = Packet::create_vxlan_packet(
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
            4789,
            9090,
            false,
            2000,
            _udp.clone(),
        );

        let _vxlan_tcp = Packet::create_vxlan_packet(
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
            4789,
            9090,
            false,
            2000,
            _tcp.clone(),
        );

        let _vxlanv6_udp = Packet::create_vxlanv6_packet(
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
            4789,
            9090,
            false,
            2000,
            _udp.clone(),
        );

        let _vxlanv6_tcp = Packet::create_vxlanv6_packet(
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
            4789,
            9090,
            false,
            2000,
            _tcp.clone(),
        );

        let _arp_req = Packet::create_arp_packet(
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
            60,
        );

        let _arp_resp = Packet::create_arp_packet(
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
            60,
        );

        let mut ip_tcp = _tcp.clone();
        ip_tcp.remove(0);
        let mut ip_udp = _udp.clone();
        ip_udp.remove(0);
        let mut ip_tcpv6 = _tcpv6.clone();
        ip_tcpv6.remove(0);
        let mut ip_udpv6 = _udpv6.clone();
        ip_udpv6.remove(0);

        let _ip4ip4 = Packet::create_ipv4ip_packet(
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

        let _ip4ip6 = Packet::create_ipv4ip_packet(
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

        let _ip6ip4 = Packet::create_ipv6ip_packet(
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

        let _ip6ip6 = Packet::create_ipv6ip_packet(
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

        pcap_write(vec![
            _tcp.to_vec().as_slice(),
            _udp.to_vec().as_slice(),
            _icmp.to_vec().as_slice(),
            _tcpv6.to_vec().as_slice(),
            _udpv6.to_vec().as_slice(),
            _icmpv6.to_vec().as_slice(),
            _vxlan_udp.to_vec().as_slice(),
            _vxlanv6_udp.to_vec().as_slice(),
            _vxlan_tcp.to_vec().as_slice(),
            _vxlanv6_tcp.to_vec().as_slice(),
            _arp_req.to_vec().as_slice(),
            _arp_resp.to_vec().as_slice(),
            _ip4ip4.to_vec().as_slice(),
            _ip4ip6.to_vec().as_slice(),
            _ip6ip4.to_vec().as_slice(),
            _ip6ip6.to_vec().as_slice(),
        ]);
    }
    #[test]
    fn update_packet_test() {
        let mut pkt = Packet::create_tcp_packet(
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
            100,
        );
        pkt.show();
        let x: &mut Box<dyn Header> = &mut pkt["Ethernet"];
        let x: &mut Ethernet = x.into();
        x.set_etype(0x86dd);
        x.show();

        let new_pkt = pkt.clone();
        new_pkt.show();
        pkt.show();
        assert_eq!(true, pkt.compare(&new_pkt));
        assert_eq!(true, pkt.compare_with_slice(new_pkt.to_vec().as_slice()));

        // immutable
        let x: &Ethernet = pkt.get_header("Ethernet").unwrap();
        println!("{}", x.etype());
        x.show();

        let y: &Box<dyn Header> = &pkt["Ethernet"];
        let x: &Ethernet = y.into();
        println!("{}", x.etype());
        x.show();

        let x: &Ethernet = (&pkt["Ethernet"]).into();
        println!("{}", x.etype());
        x.show();

        // mutable
        let x: &mut Ethernet = pkt.get_header_mut("Ethernet").unwrap();
        x.set_etype(0x9999);
        x.show();

        let x: &mut Box<dyn Header> = &mut pkt["Ethernet"];
        let x: &mut Ethernet = x.into();
        x.set_etype(0x9999);
        x.show();
    }
    #[test]
    fn pktgen_perf_test() {
        let cnt = 300000;
        let pktlen: usize = 100;
        let mut pkt = Packet::create_tcp_packet(
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
            pktlen,
        );

        // new packet in every iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let p = Packet::create_tcp_packet(
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
                pktlen,
            );
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
            let x: &mut Ethernet = (&mut pkt["Ethernet"]).into();
            x.set_etype(i % 0xFFFF);
            let p = pkt.clone();
            p.to_vec();
            // p.show();
        }
        println!("Update+Clone {} packets : {:?}", cnt, start.elapsed());
    }
}
