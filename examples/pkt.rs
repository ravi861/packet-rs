extern crate rscapy;

use rscapy::headers::Ethernet;

fn main() {
    let e = Ethernet::new();
    e.show()
}
