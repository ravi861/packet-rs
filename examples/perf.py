from ptf.testutils import *
from rscapy import *
from datetime import datetime
import copy

import scapy.layers.l2
import scapy.layers.inet

iEther = scapy.layers.l2.Ether
iIP = scapy.layers.inet.IP
iTCP = scapy.layers.inet.TCP

'''
Results from running this script:
0:00:15.593012 100000 Scapy
0:00:07.370621 100000 Scapy clone
0:00:06.082119 10000  PTF
0:00:00.998611 10000  PTF clone
0:00:00.493261 100000 Rscapy construct tcp
0:00:00.173716 100000 Rscapy create_tcp_packet
0:00:00.033968 100000 Rscapy clone
'''

cnt = 100000
tstart = datetime.now()
for i in range(0,cnt):
    p = iEther() / iIP() / iTCP()
print(datetime.now() - tstart, cnt, "Scapy")

pkt = iEther() / iIP() / iTCP()
tstart = datetime.now()
for i in range(0,cnt):
    p = copy.deepcopy(pkt)
print(datetime.now() - tstart, cnt, "Scapy clone")

tstart = datetime.now()
for i in range(0,10000):
    p = simple_tcp_packet()
print(datetime.now() - tstart, 10000, " PTF")

pkt = simple_tcp_packet()
tstart = datetime.now()
for i in range(0,10000):
    p = copy.deepcopy(pkt)
print(datetime.now() - tstart, 10000, " PTF clone")

tstart = datetime.now()
for i in range(0,cnt):
    p = Packet(100) + Ethernet() + IPv4() + TCP()
print(datetime.now() - tstart, cnt, "Rscapy construct tcp")

tstart = datetime.now()
for i in range(0,cnt):
    p = Packet.create_tcp_packet("00:11:11:11:11:11", "00:06:07:08:09:0a", False,
                             10, 3, 5, "10.10.10.1", "11.11.11.1", 0, 64, 115,
                             0, [], 8888, 9090, 100, 101, 5, 0, 2, 0, 0, False,
                             100)
print(datetime.now() - tstart, cnt, "Rscapy create_tcp_packet")

pkt = Packet.create_tcp_packet("00:11:11:11:11:11", "00:06:07:08:09:0a", False,
                             10, 3, 5, "10.10.10.1", "11.11.11.1", 0, 64, 115,
                             0, [], 8888, 9090, 100, 101, 5, 0, 2, 0, 0, False,
                             100)
tstart = datetime.now()
for i in range(0,cnt):
    p = pkt.clone_me()
print(datetime.now() - tstart, cnt, "Rscapy clone")