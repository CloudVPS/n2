import os, time

import win32api, win32net, win32pdh

from n2.platform import blank
from construct import Container

class win32(blank):
    def __init__(self, packet):
        super(win32, self).__init__(packet)
        packet.os = 'Windows'
        packet.hostname = win32api.GetComputerName()

    def querysinglecounter(self, path, fmt):
        h = win32pdh.OpenQuery()
        c = win32pdh.AddCounter(h, path)
        win32pdh.CollectQueryData(h)
        discard, v = win32pdh.GetFormattedCounterValue(c, fmt)
        return v
        
    def getusers(self):
        users = []
        resumeHandle = 0
        while True:
                (moreusers, total, resumeHandle) = win32net.NetWkstaUserEnum(None, 1, resumeHandle)
                users.extend(moreusers)
                if not resumeHandle:
                    break
        ret = []
        print users
        for u in users:
            ret.append(Container(username=u['username'],line=u['logon_domain'],host=0))
        return ret
    
    def getprocesses(self):
        junk, instances = win32pdh.EnumObjectItems(None,None,"process", win32pdh.PERF_DETAIL_WIZARD)
        proc_ids=[]
        proc_dict={}
        for instance in instances:
          if proc_dict.has_key(instance):
              proc_dict[instance] = proc_dict[instance] + 1
          else:
              proc_dict[instance]=0
        for instance, max_instances in proc_dict.items():
          for inum in xrange(max_instances+1):
              hq = win32pdh.OpenQuery() # initializes the query handle 
              path = win32pdh.MakeCounterPath( (None,"process",instance, None, inum, "% Processor Time") )
              counter_handle=win32pdh.AddCounter(hq, path) #convert counter path to counter handle
              win32pdh.CollectQueryData(hq) #collects data for the counter 
              win32pdh.CollectQueryData(hq) #collects data for the counter 
              type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_DOUBLE)
              proc_ids.append(instance+'\t'+str(val))
              win32pdh.CloseQuery(hq) 
    
        proc_ids.sort()
        print proc_ids

    cpuquery = None
    cpuhandle = None
    def getcpu(self):
        if not self.cpuquery:
            self.cpuquery = win32pdh.OpenQuery()
            self.cpuhandle = win32pdh.AddCounter(self.cpuquery, r'\Processor(_Total)\% Idle Time')
            win32pdh.CollectQueryData(self.cpuquery)

        win32pdh.CollectQueryData(self.cpuquery)
        discard, val = win32pdh.GetFormattedCounterValue(self.cpuhandle, win32pdh.PDH_FMT_DOUBLE)
        return 100.0 - val

    diskioquery = None
    diskiohandle = None
    def getdiskio(self):
        if not self.diskioquery:
            self.diskioquery = win32pdh.OpenQuery()
            self.diskiohandles = (
              win32pdh.AddCounter(self.diskioquery, r'\PhysicalDisk(_Total)\Disk Read Bytes/sec'),
              win32pdh.AddCounter(self.diskioquery, r'\PhysicalDisk(_Total)\Disk Write Bytes/sec')
            )
            win32pdh.CollectQueryData(self.diskioquery)

        win32pdh.CollectQueryData(self.diskioquery)
        discard, r = win32pdh.GetFormattedCounterValue(self.diskiohandles[0], win32pdh.PDH_FMT_LONG)
        discard, w = win32pdh.GetFormattedCounterValue(self.diskiohandles[1], win32pdh.PDH_FMT_LONG)
        return r+w
    
    netquery = None
    nethandles = None
    def getnetwork(self, netquery=None):
        # FIXME: takes first nic instead of total
        if not self.netquery:
            self.netquery = win32pdh.OpenQuery()
            iface = win32pdh.EnumObjectItems(None, None, 'Network Interface', win32pdh.PERF_DETAIL_WIZARD, 0)[1][0]
            print iface
            rxpath = win32pdh.MakeCounterPath( (None, 'Network Interface', iface, None, 0, 'Bytes Received/sec') )
            txpath = win32pdh.MakeCounterPath( (None, 'Network Interface', iface, None, 0, 'Bytes Sent/sec') )
            self.nethandles = (
              win32pdh.AddCounter(self.netquery, rxpath),
              win32pdh.AddCounter(self.netquery, txpath)
            )
            win32pdh.CollectQueryData(self.netquery)
            
        win32pdh.CollectQueryData(self.netquery)

        discard, rx = win32pdh.GetFormattedCounterValue(self.nethandles[0], win32pdh.PDH_FMT_LONG)
        discard, tx = win32pdh.GetFormattedCounterValue(self.nethandles[1], win32pdh.PDH_FMT_LONG)
        return rx, tx

    def uptime(self):
        return self.querysinglecounter(r'\System\System Up Time', win32pdh.PDH_FMT_LONG)
        
    def nproc(self):
        return self.querysinglecounter(r'\System\Processes', win32pdh.PDH_FMT_LONG)

    def nrun(self):
        return self.querysinglecounter(r'\System\Processor Queue Length', win32pdh.PDH_FMT_LONG)

    def run(self):
        # nalezen: win32pdh
        # win32process.EnumProcesses()
        
        # h = win32service.OpenSCManager(None, None, 5 ???)
        # win32service.EnumServicesStatus(h)
        
        # win32ts.WTSEnumerateSessions(..)
        
        self.packet.ts = int(time.time())
            # for d in disks:   # win32net.NetServerDiskEnum(..)
        #     win32api.GetFreeDiskSpaceEx('c:\') -> [0] = free [1] = total [2] = free ???
        mem = win32api.GlobalMemoryStatus()
        self.packet.kmemfree = mem['AvailPhys']/1024
        self.packet.kswapfree = mem['AvailPageFile']/1024
        self.packet.ttyrec = self.getusers()
        rx,tx = self.getnetwork()
        self.packet.netout = tx/1024
        self.packet.netin = rx/1024
        self.packet.cpu = self.getcpu()
        self.packet.uptime = self.uptime()
        self.packet.nproc = self.nproc()
        self.packet.nrun = self.nrun()
        self.packet.diskio = self.getdiskio() / 1024


        
