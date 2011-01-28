from construct import *

import time, hashlib, itertools, os, socket, struct, pprint
from collections import defaultdict

def uptimeencoder(x, ctx):
    maxts = 0x4000
    if x < maxts:
        return x
    elif x/60 < maxts:
        return (x/60) | 0x4000
    elif x/3600 < maxts:
        return (x/3600) | 0x8000
    else:
        return (x/86400) | 0xc000

def uptimedecoder(x, ctx):
    if x & 0xc000 == 0:
        return x
    if x & 0xc000 == 0x4000:
        return (x & 0x3fff) * 60
    if x & 0xc000 == 0x8000:
        return (x & 0x3fff) * 3600
    return (x & 0x3fff) * 86400

def ULInt24(name):
    return ExprAdapter(
      Field(name,3),
      encoder = lambda obj, ctx: chr(obj & 0xff)+chr((obj >> 8) & 0xff)+chr((obj>>16)&0xff),
      decoder = lambda obj, ctx: ord(obj[0]) + (ord(obj[1])<<8) + (ord(obj[2])<<16)
    )

def ratioAdapter(name, format, ratio):
    return ExprAdapter(format(name),
       encoder = lambda obj, ctx: obj * float(ratio),
       decoder = lambda obj, ctx: obj / float(ratio)
     )

structure = Struct('n2packet',
    PascalString('hostname'),
    EmbeddedBitStruct(
      Enum(
        BitField('hw', 4),
        i386 = 0,
        i686 = 0, # reverse mapping for 0 is ambiguous!
        x86_64 = 1,
        PowerPC = 2,
        MIPS = 3,
        Sparc = 4,
        Alpha = 5,
        PARISC = 6,
        Other = 7
      ),
      Enum(
        BitField('os', 4),
        Linux = 0,
        BSD = 1,
        Solaris = 2,
        IRIX = 3,
        AIX = 4,
        HPUX = 5,
        Darwin = 6,
        Windows = 7,
        Other = 8
      )
    ),
  
    ExprAdapter(ULInt16('load1'),
      encoder = lambda obj, ctx: obj*100.0,
      decoder = lambda obj, ctx: obj/100.0
    ),
    ExprAdapter(ULInt8('cpu'),
      encoder = lambda obj, ctx: obj * 255/100,
      decoder = lambda obj, ctx: obj * 100.0/255
    ),
    ULInt24('diskio'),
    ULInt32('services'), # FIXME
    ExprAdapter(ULInt16('uptime'),
      encoder = uptimeencoder,
      decoder = uptimedecoder
    ),
    ULInt24('ts'),
    ULInt8('nrun'),
    ULInt16('nproc'),
    ULInt24('kmemfree'),
    ULInt24('kswapfree'),
    ULInt32('netin'),
    ULInt32('netout'),
    PrefixedArray(
      Struct('mrec',
        PascalString('mountpoint'),
        PascalString('fstype'),
        ratioAdapter('usage', ULInt32, 10)
      ),
    ),
    PrefixedArray(
      Struct('toprec',
        PascalString('username'),
        ULInt32('pid'),
        ratioAdapter('pcpu', ULInt16, 100),
        ratioAdapter('pmem', ULInt16, 100),
        ULInt24('secrun'),
        PascalString('ptitle')
      )
    ),
    PrefixedArray(
      Struct('prec',
        ULInt16('portno'),
        ULInt16('nestab'),
        ULInt16('nother')
      )
    ),
    PrefixedArray(
      Struct('ttyrec',
        PascalString('line'),
        PascalString('username'),
        ULInt32('host')
      )
    ),
    PrefixedArray(
      Struct('httprec',
        PascalString('vhost'),
        ULInt16('count')
      )
    ),
    PrefixedArray(
      Struct('xenvps',
        PascalString('vpsid'),
        ratioAdapter('pcpu', ULInt16, 100),
        ratioAdapter('ram', ULInt16, 1/16.0),
        ULInt8('ncpu')
      )
    )
)

class CsumError(Exception):
    pass

class n2packet(object):
    """n2 packet builder"""
    def __init__(self, key):
        super(n2packet, self).__init__()
        # try:
        #     maincon = structure.subcon
        # except e:
        #     print e
        #     maincon = structure
        # slots = [con.name for con in maincon.subcons]
        # self.__slots__ = slots
        self.key = key
    
    def sign(self, p):
        csum = hashlib.md5(p+self.key).digest()
        return csum+p
    
    def unsign(self, p):
        csum = hashlib.md5(p[16:]+self.key).digest()
        if p[:16] == csum:
            return p[16:]
        raise CsumError
    
    def struct(self):
        self.mrec = self.mrec[:4]
        self.toprec = self.toprec[:8]
        self.prec = self.prec[:10]
        self.ttyrec = self.ttyrec[:10]
        return structure.build(
          Container(
            **self.__dict__
          )
        )

    def fromstruct(self, p):
        """parse packet representation"""
        self.__dict__.update(structure.parse(p).__dict__)
        
    def packet(self):
        return self.sign(self.struct())
    
    def frompacket(self, p):
        self.fromstruct(self.unsign(p))

if __name__ == '__main__':
    n = n2packet('dontcare')
    # n.hostname='tesla'
    # n.uptime=86410
    # n.numproc=100
    # n.numrunproc=70
    # n.ramfree=800
    # n.swapfree=900
    # n.netin=10000
    # n.netout=11000
    # n.loadavg=5.6
    # n.cpuusage=50
    # n.diskbw=230
    # n.hosttime = 1279813966
    # n.kmemfree = 500000
    # n.kswapfree = 600123
    # 
    # print n.frompacket(n.packet())
    
    n.fromstruct(file("packetdump.nomd5","r").read())
    pprint.pprint(n.__dict__)
    # file("n2packet.py-out","w").write(n.packet())
    # socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(n.packet(), ('127.0.0.1',4444))
