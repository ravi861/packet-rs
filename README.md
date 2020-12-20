Rust based Scapy alternative

Introduction
============
Rscapy is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and construct packets with custom headers.

make_header
===========
The core of the library is the *make_header* macro which provides a flexible way to create new headers.<br>
Describe a new header in the below format with defaults as a vector.
```
make_header! {
    <header_name> <length in bytes> (
        <field_name1> <start_bit> - <end_bit>,
        <field_name2> <start_bit> - <end_bit>,
    )
    <optional default data vec>
};
```

Define a header
---------------
Add a new header by using the *make_header* macro. This automatically creates a set_*field*() and a get() helper methods for each field.

```rust
#[macro_use]
extern crate rscapy;

use rscapy::headers::*;
use rscapy::Packet;

make_header!(
Vlan 4
(
    pcp: 0-2,
    cfi: 3-3,
    vid: 4-15,
    etype: 16-31
)
vec![0x0, 0xa, 0x8, 0x0]      // <= optional default data
);
```
3 ways to create a header
-------------------------
```rust
// Call new on the vlan header
let vlan = Vlan::new();

// Pass a data buffer as an argument
let vlan = Vlan([0x00, 0x0a, 0x08, 0x10]);

// Use an associate function from Packet struct
let vlan = Packet::vlan(2, 1, 10, 0x086dd);
```
make_header! generates helper methods and associated functions for each header and fields
```rust
vlan.octets();                // get the vlan header as a byte array
vlan.cfi();                   // fetch the cfi field value
vlan.set_cfi(1);              // set the cfi field value
let vlan_new = vlan.clone();  // clone the packet
vlan.show();                  // display the vlan header

Output of show():
Raw: 00 0a 08 00
#### Vlan             Size   Data
-------------------------------------------
pcp                 :    3 : 02
cfi                 :    1 : 01
vid                 :   12 : 00 10
etype               :   16 : 08 00
```
Create a Packet
---------------
A packet is an ordered list of headers. Push headers as required into a packet.
```rust
let mut pkt = Packet::new(100);
pkt.push(Ethernet::new()));
pkt.push(IPv4::new());
pkt.show()

#### Ethernet         Size   Data
-------------------------------------------
dst                 :   48 : 00 01 02 03 04 05
src                 :   48 : 00 06 07 08 09 0a
etype               :   16 : 08 00
#### IPv4             Size   Data
-------------------------------------------
version             :    4 : 04
ihl                 :    4 : 05
diffserv            :    8 : 00
total_len           :   16 : 00 14
identification      :   16 : 00 33
flags               :    3 : 02
frag_startset       :   13 : 06 29
ttl                 :    8 : 64
protocol            :    8 : 06
header_checksum     :   16 : fa ec
src                 :   32 : c0 a8 00 01
dst                 :   32 : c0 a8 00 02

// access ethernet header immutable
let y: &Ethernet<Vec<u8>> = (&pkt["Ethernet"]).into();
println!("{}", x.etype());

// access ethernet header mutable
let x: &mut Ethernet<Vec<u8>> = (&mut pkt["Ethernet"]).into();
x.set_etype(0x1111);
```