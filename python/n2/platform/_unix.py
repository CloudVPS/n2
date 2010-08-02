import os, time

from n2.platform import blank

class unix(blank):
    """n2 packet builder"""
    def __init__(self, packet):
        super(unix, self).__init__(packet)
        (packet.os, packet.hostname, _, _, packet.hw) = os.uname()
    
    def run(self):
        self.packet.ts = int(time.time())
