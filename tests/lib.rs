#[macro_use]
extern crate rscapy;

use rscapy::headers::*;
use rscapy::packet::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_header_octets_test() {
        let mut ips = Vec::new();
        ips.push(String::from("FFFF::FFFF").to_ipv6_bytes());
        ips.push(String::from("7FFF::FFFF").to_ipv6_bytes());
        ips.push(String::from("FFF7::FFFF").to_ipv6_bytes());
        ips.push(String::from("FFFF::FFF7").to_ipv6_bytes());
        ips.push(String::from("FFFF::7FFF").to_ipv6_bytes());
        ips.push(String::from("1111::FFFF").to_ipv6_bytes());
        ips.push(String::from("8888::FFFF").to_ipv6_bytes());
        ips.push(String::from("FFFF::1111").to_ipv6_bytes());
        ips.push(String::from("FFFF::8888").to_ipv6_bytes());
        ips.push(String::from("8888::1111").to_ipv6_bytes());
        ips.push(String::from("2001:3001:4001::FFFF").to_ipv6_bytes());
        ips.push(String::from("FFFF:4001:3001::2001").to_ipv6_bytes());
        ips.push(String::from("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").to_ipv6_bytes());
        ips.push(String::from("1111:1111:1111:1111:1111:1111:1111:1111").to_ipv6_bytes());
        ips.push(String::from("8888:8888:8888:8888:8888:8888:8888:8888").to_ipv6_bytes());
        ips.push(String::from("FFFF:4001:3001:2001:2001:3001:4001:FFFF").to_ipv6_bytes());
        ips.push(String::from("2001:3001:4001:FFFF:FFFF:4001:3001:2001").to_ipv6_bytes());

        let mut ipv6 = IPv6::new();
        for a in ips {
            ipv6.set_bytes(IPv6::<Vec<u8>>::dst_msb(), IPv6::<Vec<u8>>::dst_lsb(), &a);
            let b = ipv6.get_bytes(IPv6::<Vec<u8>>::dst_msb(), IPv6::<Vec<u8>>::dst_lsb());
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
    fn ethernet_header_test() {
        let mut eth = Ethernet::new();
        println!("{:?}", eth.0);
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

        let data = [
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x81, 0x00,
        ];
        let ethernet = Ethernet(data);
        ethernet.as_slice();
        ethernet.show();
    }
    #[test]
    fn vlan_header_test() {
        let vlan = Vlan::new();
        vlan.show();

        let data = [0x00, 0x0a, 0x08, 0x00];
        let vlan = Vlan(data);
        vlan.as_slice();
        vlan.show();
    }
    #[test]
    fn ip_header_test() {
        let ipv4 = IPv4::new();
        ipv4.show();

        let data = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x33, 0x40, 0xdd, 0x40, 0x06, 0xfa, 0xec, 0xa, 0xa, 0xa,
            0x1, 0xb, 0xb, 0xb, 0x1,
        ];
        let ipv4 = IPv4(data);
        ipv4.as_slice();
        ipv4.show();

        let data: Vec<u8> = vec![0; IPv6::<Vec<u8>>::size()];
        let ipv6 = IPv6(data);
        ipv6.as_slice();
        ipv6.show();
    }
    #[test]
    fn create_packet_test() {
        let mut pkt = rscapy::create_tcp_packet(
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
        let y: &mut Box<dyn Header> = pkt.get_header_mut("Ethernet");
        let x: &mut Ethernet<Vec<u8>> = Ethernet::<Vec<u8>>::to_concrete_mut(y);
        x.show();
        x.set_etype(0x86dd);
        x.show();
        pkt.refresh();

        let new_pkt = pkt.clone();
        new_pkt.show();
        pkt.show();
        assert_eq!(true, pkt.compare(&new_pkt));
        assert_eq!(true, pkt.compare_with_slice(new_pkt.as_slice()));

        let pkt = rscapy::create_udp_packet(
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
            80,
            9090,
            false,
            129,
        );
        // pkt.show();

        let pkt = rscapy::create_tcpv6_packet(
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
            80,
            9090,
            100,
            101,
            0,
            0,
            1,
            0,
            0,
            100,
        );
        // pkt.show();

        let pkt = rscapy::create_udpv6_packet(
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
            80,
            9090,
            129,
        );
        // pkt.show();
    }
}
