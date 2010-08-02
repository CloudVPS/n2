import socket
import pprint

from n2.packet import n2packet

def run(args=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0",4444))
    packet = n2packet('dontcare')
    while True:
        pdata = s.recv(4096)
        packet.frompacket(pdata)
        pprint.pprint(packet.__dict__)