class blank(object):
    def __init__(self, packet):
        super(blank, self).__init__()
        self.packet = packet
        self.packet.hostname = 'Amnesiac'
        self.packet.hw = 'Other'
        self.packet.os = 'Other'
        self.packet.load1 = 0
        self.packet.cpu = 0
        self.packet.diskio = 0
        self.packet.services = 0
        self.packet.uptime = 0
        self.packet.ts = 0
        self.packet.nrun = 0
        self.packet.nproc = 0
        self.packet.kmemfree = 0
        self.packet.kswapfree = 0
        self.packet.netin = 0
        self.packet.netout = 0
        self.packet.mrec = []
        self.packet.toprec = []
        self.packet.prec = []
        self.packet.ttyrec = []
        self.packet.httprec = []
        self.packet.xenvps = []
        
    def run(self):
        pass