import n2.platform
from n2.packet import n2packet
import pprint, time, socket, sys

def run(args=None):
    ip, port, key = sys.argv[1:]
    port = int(port)
    packet = n2packet(key)
    source = n2.platform.this(packet)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        source.run()
        print ip,port
        s.sendto(packet.packet(), (ip, port))
        time.sleep(2)

if __name__ == '__main__':
    run()
    