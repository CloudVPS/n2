from distutils.core import setup

from glob import glob

import py2exe
class TargetClass:
    pass
    
service = TargetClass()

service.modules=['n2.win32.service']
service.cmdline_style='pywin32'
service.dest_base='n2txd'

data_files = [("Microsoft.VC90.CRT", glob(r'c:\vcrt\*.*'))]
setup(service=[service], console=['n2/win32/configure.py'], data_files=data_files)