from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

'''print ("***Print all packets in this pcap file***")
print (packets.show())

print ("***Print all TCP packets in this pcap file***")
print (packets[TCP].show())

print ("***Print the first TCP packet content***")
print (packets[TCP][0].show())

print ("***Get data of this packet***")
print (f"     src IP: {packets[TCP][0][1].src}")     # in IP layer
print (f"     dst IP: {packets[TCP][0][1].dst}")     # in IP layer
print (f"   src port: {packets[TCP][0][2].sport}") # in TCP layer
print (f"   dst port: {packets[TCP][0][2].dport}") # in TCP layer
print (f"packet size: {len(packets[TCP][0])} bytes")



print ("***Count number of TCP packets***")'''

packets = rdpcap("../out/TCP_h3.pcap") 

pbt, pbu = 0, 0
packett = [] 
packetu = []
for packet in packets[TCP]:
    if packet[TCP].dport == 7777:
        packett.append(packet)
        nt = len(packet)
        pbt += nt
    else:
        packetu.append(packet)
        nu = len(packet)
        pbu += nu

tt = packett[-1].time - packett[0].time
tu = packetu[-1].time - packetu[0].time
throughputt = pbt*8/(2**20*tt)
throughputu = pbu*8/(2**20*tu)
print(f'--- TCP ---\n\nFlow1(h1->h3):{throughputt} Mbps\n\nFlow2(h1->h3):{throughputu} Mbps\n')

packets = rdpcap("../out/TCP_h4.pcap") 

pbt, pbu = 0, 0
packett = [] 
packetu = []
for packet in packets[TCP]:
    if packet[TCP].dport == 7777:
        packett.append(packet)
        nt = len(packet)
        pbt += nt
    else:
        packetu.append(packet)
        nu = len(packet)
        pbu += nu

tt = packett[-1].time - packett[0].time
throughputt = pbt*8/(2**20*tt)

print(f'Flow3(h2->h4):{throughputt} Mbps\n\n')


packets = rdpcap("../out/UDP_h3.pcap") 

pbt, pbu = 0, 0
packett = [] 
packetu = []
for packet in packets[UDP]:
    if packet[UDP].dport == 7777:
        packett.append(packet)
        nt = len(packet)
        pbt += nt
    else:
        packetu.append(packet)
        nu = len(packet)
        pbu += nu


tt = packett[-1].time - packett[0].time
tu = packetu[-1].time - packetu[0].time
throughputt = pbt*8/(2**20*tt)
throughputu = pbu*8/(2**20*tu)

print(f'--- UDP ---\n\nFlow1(h1->h3):{throughputt} Mbps\n\nFlow2(h1->h3):{throughputu} Mbps\n')

packets = rdpcap("../out/UDP_h4.pcap") 

pbt, pbu = 0, 0
packett = [] 
packetu = []
for packet in packets[UDP]:
    if packet[UDP].dport == 7777:
        packett.append(packet)
        nt = len(packet)
        pbt += nt
    else:
        packetu.append(packet)
        nu = len(packet)
        pbu += nu

tt = packett[-1].time - packett[0].time
throughputt = pbt*8/(2**20*tt)

print(f'Flow3(h2->h4):{throughputt} Mbps\n\n')

