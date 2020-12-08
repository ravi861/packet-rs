Rust based Scapy alternative

Introduction
============
Rscapy is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and construct packets with custom headers.

make_header
===========
The core of the library is the *make_header* macro which provides a flexible way to create new headers.<br>
Describe a new header in the below format.
```
make_header!(
    <header_name> <length in bytes>
    <field_name1> <start_bit> - <end_bit>,
    <field_name2> <start_bit> - <end_bit>,
)
```

Create a header
---------------
Add a new header by using the *make_header* macro. This automatically creates a set_field() and a get() helper methods for each field.

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
);
```
3 ways to create a header
-------------------------
Pass a data buffer as an argument
```rust
let data = [0x00, 0x0a, 0x08, 0x10];
let vlan = Vlan(data);
vlan.octets();                // get the vlan header as a byte array
vlan.show();                  // display the vlan header
vlan.cfi();                   // fetch the cfi field value
vlan.set_cfi(1);              // get the cfi field value
let vlan_new = vlan.clone();  // clone the packet
```
Create empty header and fill in data
```rust
let data = [0, 0, 0, 0];
let mut vlan = Vlan(data);
vlan.set_pcp(2);
vlan.set_cfi(1);
vlan.set_vlan(10);
vlan.set_etype(0x800);
vlan.show();
Output of show:
Bytes: 00 0a 08 00
#### Vlan             Size   Data
-------------------------------------------
pcp                 :    3 : 02
cfi                 :    1 : 01
vid                 :   12 : 00 10
etype               :   16 : 08 00
```
Use an associate method from Packet
```rust
let vlan = Packet::vlan(2, 1, 10, 0x086dd);
vlan.show();
#### Vlan             Size   Data
-------------------------------------------
pcp                 :    3 : 02
cfi                 :    1 : 01
vid                 :   12 : 00 10
etype               :   16 : 86 dd
```


Create a Packet
---------------
A packet is an ordered collection of headers. Push headers as required into a packet.
```rust
extern crate rscapy;
use rscapy::Packet;

dst = "00:01:02:03:04:05";
src = "00:06:07:08:09:0a";
let mut pkt = Packet::new();
pkt.push("ethernet", Box::new(Packet::ethernet(dst, src, 0x8100)));
pkt.push("vlan", Box::new(Packet::vlan(2, 1, 10, 0x0800)));
pkt.show()

#### packet ####
00 01 02 03 04 05 00 06 07 08 09 0a 81 00 30 0a
08 00
#### Ethernet         Size   Data
-------------------------------------------
dst                 :   48 : 00 01 02 03 04 05
src                 :   48 : 00 06 07 08 09 0a
etype               :   16 : 81 00
#### IPv4             Size   Data
#### Vlan             Size   Data
-------------------------------------------
pcp                 :    3 : 02
cfi                 :    1 : 01
vid                 :   12 : 00 10
etype               :   16 : 86 dd
```