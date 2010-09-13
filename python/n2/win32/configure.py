import os, time, sys

from n2.win32.service import getconfig
from n2.win32.service import setconfig

def configure(argv):
    if len(argv):
        setconfig(*argv)
    else:
        c = getconfig()
        print 'Current config:'
        print 'IP = %s' % c[0]
        print 'port = %s' % c[1]
        print 'key = %s' % c[2]
        print 'Use configure <IP> <port> <key> to configure'
    
if __name__ == '__main__':
    configure(sys.argv[1:])