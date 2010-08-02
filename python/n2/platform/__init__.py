from n2.platform._blank import blank

this = blank

import sys

if sys.platform == 'win32':
    from n2.platform._win32 import win32
    this = win32
else:
    from n2.platform._unix import unix
    this = unix

