from distutils.core import setup
import py2exe
class TargetClass:
    pass
    
service = TargetClass()

service.modules=['n2.win32.service']
service.cmdline_style='pywin32'
service.dest_base='n2txd'

setup(service=[service], console=['n2/win32/configure.py'])