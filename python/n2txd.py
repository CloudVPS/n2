#!/usr/bin/env python
import sys

import n2.txd

import win32serviceutil
from n2.platform._win32 import n2txdservice

print 'name: %s' % __name__
if __name__ == '__main__':
    n2.txd.run(sys.argv[1:])