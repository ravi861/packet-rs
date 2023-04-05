use std::convert::TryFrom;

pub const MAC_LEN: usize = 6;
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

pub const ETHERNET_HDR_LEN: usize = 14;
pub const VLAN_HDR_LEN: usize = 4;
pub const GRE_HDR_LEN: usize = 4;
pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const UDP_HDR_LEN: usize = 8;
pub const TCP_HDR_LEN: usize = 20;
pub const VXLAN_HDR_LEN: usize = 8;
pub const ERSPAN2_HDR_LEN: usize = 8;
pub const ERSPAN3_HDR_LEN: usize = 12;

pub const UDP_PORT_VXLAN: u16 = 4789;

pub enum IpType {
    V4 = 4,
    V6 = 6,
}
impl TryFrom<u8> for IpType {
    type Error = String;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == IpType::V4 as u8 => Ok(IpType::V4),
            x if x == IpType::V6 as u8 => Ok(IpType::V6),
            _ => Err(format!("Unsupported IpType {}", v)),
        }
    }
}

pub enum IpProtocol {
    ICMP = 1,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    GRE = 47,
    ICMPV6 = 58,
}
impl TryFrom<u8> for IpProtocol {
    type Error = String;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == IpProtocol::ICMP as u8 => Ok(IpProtocol::ICMP),
            x if x == IpProtocol::IPIP as u8 => Ok(IpProtocol::IPIP),
            x if x == IpProtocol::TCP as u8 => Ok(IpProtocol::TCP),
            x if x == IpProtocol::UDP as u8 => Ok(IpProtocol::UDP),
            x if x == IpProtocol::IPV6 as u8 => Ok(IpProtocol::IPV6),
            x if x == IpProtocol::GRE as u8 => Ok(IpProtocol::GRE),
            x if x == IpProtocol::ICMPV6 as u8 => Ok(IpProtocol::ICMPV6),
            _ => Err(format!("Unsupported IpProtocol {}", v)),
        }
    }
}

pub enum EtherType {
    IPV4 = 0x0800,
    ARP = 0x0806,
    DOT1Q = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847,
    ERSPANII = 0x88be,
    ERSPANIII = 0x22eb,
}
impl TryFrom<u16> for EtherType {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == EtherType::IPV4 as u16 => Ok(EtherType::IPV4),
            x if x == EtherType::ARP as u16 => Ok(EtherType::ARP),
            x if x == EtherType::DOT1Q as u16 => Ok(EtherType::DOT1Q),
            x if x == EtherType::IPV6 as u16 => Ok(EtherType::IPV6),
            x if x == EtherType::MPLS as u16 => Ok(EtherType::MPLS),
            x if x == EtherType::ERSPANII as u16 => Ok(EtherType::ERSPANII),
            x if x == EtherType::ERSPANIII as u16 => Ok(EtherType::ERSPANIII),
            _ => Err(format!("Unsupported EtherType {}", v)),
        }
    }
}

pub enum ErspanVersion {
    II = 1,
    III = 2,
}
impl TryFrom<u16> for ErspanVersion {
    type Error = String;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == ErspanVersion::II as u16 => Ok(ErspanVersion::II),
            x if x == ErspanVersion::III as u16 => Ok(ErspanVersion::III),
            _ => Err(format!("Unsupported ErspanVersion {}", v)),
        }
    }
}
