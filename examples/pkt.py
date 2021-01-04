from rscapy import *

# create an ethernet header
eth = Ethernet()
eth.show()

# get ethertype using idiomatic python get
etype = eth.etype
print(etype)

# set ethertype using idiomatic python set
eth.etype = 0x8100
eth.show()

# use the Packet helper function to create ethernet header
eth = Packet.ethernet("00:11:11:11:11:11", "00:11:11:11:11:11", 0x8100)
eth.show()

# create a new packet of size 100
pkt = Packet(100)
# append above ethernet header
pkt = pkt + Ethernet()
pkt.show()

# headers can also be appended to obtained a packet
pkt = Ethernet() + Vxlan()
pkt.show()

# create a TCP packet appending each header
pkt = Packet(100) + Ethernet() + IPv4() + TCP()
pkt.show()

# create a TCP packet using the Packet helper function
pkt = Packet.create_tcp_packet("00:11:11:11:11:11", "00:06:07:08:09:0a", False,
                               10, 3, 5, "10.10.10.1", "11.11.11.1", 0, 64,
                               115, 0, [], 8888, 9090, 100, 101, 5, 0, 2, 0, 0,
                               False, 100)
# convert packet to byte array
pkt.to_vec()

# duplicate a packet using clone method
new_pkt = pkt.clone()
