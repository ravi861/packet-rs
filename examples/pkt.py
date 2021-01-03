from rscapy import *

x = Ethernet()
x.show()
etype = x.etype
print(etype)
x.etype = 0x8100
x.show()

v = Vxlan()
v.show()

p = Packet.create_tcp_packet("00:11:11:11:11:11", "00:06:07:08:09:0a", False,
                             10, 3, 5, "10.10.10.1", "11.11.11.1", 0, 64, 115,
                             0, [], 8888, 9090, 100, 101, 5, 0, 2, 0, 0, False,
                             100)
p.to_vec()

p = Packet.create_ipv4_packet("00:11:11:11:11:11", "00:06:07:08:09:0a", False,
                              10, 3, 5, "10.10.10.1", "11.11.11.1", 6, 0, 64,
                              115, 0, [], 100)
p.show()

e = Packet.ethernet("00:11:11:11:11:11", "00:11:11:11:11:11", 0x8100)
e.show()

p = p + e
p.show()

x = e + v
x.show()

pkt = Packet(200)
e = Ethernet()
e.etype = 0x8100
v = Vlan()
i = IPv4()
u = UDP()
pkt = pkt + e + v + i + u
pkt.show()

pkt = Packet(100) + Ethernet() + IPv4() + TCP()
pkt.show()
