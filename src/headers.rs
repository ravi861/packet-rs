pub use ::bitfield::bitfield;
pub use ::bitfield::BitRange;
pub use paste::paste;

pub trait Header {
    fn show(&self);
    fn octets(&self) -> Vec<u8>;
}

#[macro_export]
macro_rules! make_header {
    ( $name: ident $size: literal ($($field: ident: $ty: literal: $off: literal),*) ) => {
        paste! {
            bitfield! {
                pub struct $name(MSB0 [u8]);
                u32;
                $(
                    pub $field, [<set_ $field>]: $ty, $off;
                )*
            }
            impl<T: AsMut<[u8]> + AsRef<[u8]>> $name<T> {
                $(
                    pub fn [<$field _size>](&self) -> u32 {
                        $ty - $off + 1
                    }
                )*
                pub fn show(&self) {
                    println!("#### {:16} {} {}", stringify!($name), "Size  ", "Data");
                    println!("-------------------------------------------");
                    $(
                    print!("{:20}: {:4} : ", stringify!($field), $ty - $off + 1);
                    if (($ty - $off + 1) <= 8) {
                        let x: u8 = self.bit_range($ty, $off);
                        print!("{:02}", x);
                    } else if (($ty - $off + 1)%8 == 0){
                        let d = ($ty - $off + 1)/8;
                        for i in ($off..(d*8 + $off)).step_by(8) {
                            let x: u8 = self.bit_range(i + 7, i);
                            print!("{:02x} ", x);
                        }
                    } else {
                        let d = ($ty - $off + 1)/8;
                        let r = ($ty - $off + 1)%8;
                        for i in ($off..(d*8 + $off)).step_by(8) {
                            let x: u8 = self.bit_range(i + 7, i);
                            print!("{:02} ", x);
                        }
                        let x: u8 = self.bit_range($ty, $ty - r);
                        print!("{:02}", x);
                    }
                    println!();
                    )*
                }
                pub fn bytes(&self) {
                    for i in (0..$size*8).step_by(8) {
                        let x: u8 = self.bit_range(i + 7, i);
                        print!("{:02x} ", x);
                        if (i == 120) {
                            println!();
                        }
                    }
                    println!();
                }
                pub fn octets(&self) -> Vec<u8> {
                    // let mut x: [u8; $size] = [0; $size];
                    let mut x: Vec<u8> = vec![0; $size];
                    for i in (0..$size*8).step_by(8) {
                        x[i/8] = self.bit_range(i + 7, i);
                    }
                    x
                }
            }
            impl Header for $name<Vec<u8>> {
                fn show(&self) {
                    self.show();
                }
                fn octets(&self) -> Vec<u8>{
                    self.octets()
                }
            }
        }
    }
}

// vlan header
make_header!(
Ethernet 14
(
    dst: 47: 0,
    src: 95: 48,
    etype: 111: 96
)
);

// ethernet header
make_header!(
Vlan 4
(
    pcp: 2: 0,
    cfi: 3: 3,
    vid: 15: 4,
    etype: 31: 16
)
);

// ipv4 header
make_header!(
IPv4 20
(
    version: 3: 0,
    ihl: 7: 4,
    diffserv: 15: 8,
    total_len: 31: 16,
    identification: 47: 32,
    flags: 50: 48,
    frag_offset: 63: 51,
    ttl: 71: 64,
    protocol: 79: 72,
    header_checksum: 95: 80,
    src: 127: 96,
    dst: 159: 128
)
);

// ipv6 header
make_header!(
IPv6 40
(
    version: 3: 0,
    traffic_class: 11: 4,
    flow_label: 31: 12,
    payload_len: 47: 32,
    next_hdr: 55: 48,
    hop_limit: 63: 56,
    src: 191: 64,
    dst: 319: 192
)
);

// tcp header
make_header!(
TCP 20
(
    src: 15: 0,
    dst_port: 31: 16,
    seq_no: 63: 32,
    ack_no: 95: 64,
    data_offset: 99: 96,
    res: 103: 100,
    flags: 111: 104,
    window: 127: 112,
    checksum: 143: 128,
    urgent_ptr: 159: 144
)
);

// udp header
make_header!(
UDP 8
(
    src: 15: 0,
    dst: 31: 16,
    length: 47: 32,
    checksum: 63: 48
)
);
