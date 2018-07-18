#!/usr/bin/python
import sys
import os
import csv
import subprocess
import StringIO
import re

ROOT_EUID = 0

BOLD_WEIGHT = '\x1b[1m'
NORMAL_WEIGHT = '\x1b[21m'
RED_COLOR = '\x1b[31m'
DEFAULT_COLOR = '\x1b[39m'

class CpuVendor:
    INTEL = 'intel'
    OTHER = 'other'

    MAPPING = {'GenuineIntel': INTEL}
    
    @classmethod
    def os_collect(cls):
        with open('/proc/cpuinfo') as f:
            for line in f:
                if 'vendor_id' in line:
                    vendor_name = line.split(':', 1)[1].strip()
                    return cls.MAPPING.get(vendor_name, cls.OTHER)

class PciDevice:
    BRACKETS_HEX = re.compile(r'\s*(.*?)\s*\[([0-9a-f]+)\]$', re.IGNORECASE)

    USB_CONTROLLER = '0c03'
    VGA_CONTROLLER = '0300'

    def __init__(self, slot, class_name, class_id, vendor_name, vendor_id, device_name, device_id, driver, module):
        self.slot, self.class_name, self.class_id = slot, class_name, class_id
        self.vendor_name, self.vendor_id = vendor_name, vendor_id
        self.device_name, self.device_id = device_name, device_id
        self.driver, self.module = driver, module

        if slot.endswith('.0'):
            self.is_function = False
            self.slot = slot[:-2]
        else:
            self.is_function = True

    @classmethod
    def parse_pci_dict(cls, dct):
        try:
            vendor_name, vendor_id = cls.BRACKETS_HEX.match(dct['vendor']).groups()
            device_name, device_id = cls.BRACKETS_HEX.match(dct['device']).groups()
            class_name, class_id = cls.BRACKETS_HEX.match(dct['class']).groups()
        except ValueError:
            raise ValueError('incorrect pci dict')
        return cls(dct['slot'], class_name, class_id.lower(), vendor_name, vendor_id.lower(),
                device_name, device_id.lower(), dct.get('driver', ''), dct.get('module', '')) 

    def __str__(self):
        subst = dict(self.__dict__)
        subst['class_str'] = ('%(class_name)s (%(class_id)s) %(device_name)s' % self.__dict__).ljust(70)
        if self.device_name.lower() == 'device':
            subst['device_name'] = ''
        subst['vendor_name'] = ('%(vendor_name)s' % self.__dict__).ljust(30)

        return '%(slot)s  %(class_str)s %(vendor_name)s [%(vendor_id)s:%(device_id)s]' % subst

class PciDeviceList:
    class LspciDialect(csv.excel):
        delimiter = ' '

    @classmethod
    def os_collect(cls):
        pci = subprocess.check_output(['lspci', '-k', '-nn', '-vmm'])
        item = {}
        for line in pci.splitlines():
            line = line.strip()
            if not line:
                if item:
                    yield PciDevice.parse_pci_dict(item)
                item = {}
                continue
            key, value = line.split(':', 1)
            item[key.strip().lower()] = value.strip()

        if item:
            yield PciDevice.parse_pci_dict(item)

class VmNode:
    STOPPED = 'stopped'
    RUNNING = 'running'

    def __init__(self, vmid, name, status, mem, bootdisk, pid):
        self.vmid, self.name, self.status, self.mem, self.bootdisk, self.pid = \
                vmid, name, status, mem, bootdisk, pid
    
    @classmethod
    def parse_qmlist_dict(cls, dct):
        return cls(dct['VMID'], dct['NAME'], dct['STATUS'], dct['MEM(MB)'], dct['BOOTDISK(GB)'], dct['PID']) 

    def __str__(self):
        subst = dict(self.__dict__)
        return '%(vmid)s %(name)s %(status)s %(mem)s %(bootdisk)s %(pid)s' % subst

class VmNodeList:
    class QmDialect(csv.excel):
        delimiter = ' '
        skipinitialspace=True
    
    @classmethod
    def os_collect(cls):
        qm = subprocess.check_output(['qm', 'list'])
        buf = StringIO.StringIO(qm)
        
        csv.register_dialect('qm', cls.QmDialect)
        reader = csv.DictReader(buf, dialect='qm')
        csv.unregister_dialect('qm')

        for item in reader:
            yield VmNode.parse_qmlist_dict(item)

def print_devices():
    printed_devs = []
    def perform_grouping(label, predicate):
        print BOLD_WEIGHT + label + NORMAL_WEIGHT
        for dev in PciDeviceList.os_collect():
            if dev.is_function or not predicate(dev):
                continue
            if dev.module:
                printed_devs.append(dev)
                print "%2d. %s" % (len(printed_devs), dev)
            else:
                print '%s    %s%s' % (RED_COLOR, dev, DEFAULT_COLOR)
        print

    perform_grouping("VGA CONTROLLERS (videocards)",
            lambda dev: dev.class_id == PciDevice.VGA_CONTROLLER)
    perform_grouping("USB CONTROLLERS",
            lambda dev: dev.class_id == PciDevice.USB_CONTROLLER)
    perform_grouping("OTHER DEVICES",
            lambda dev: dev.class_id not in (PciDevice.USB_CONTROLLER, PciDevice.VGA_CONTROLLER))
    
    return printed_devs

if __name__ == '__main__':
    if CpuVendor.os_collect() != CpuVendor.INTEL:
        sys.stderr.write('Non-Intel CPUs not fully supported by GeexMox. Pull requests are welcome! :)\n')

    if os.geteuid() != ROOT_EUID:
        sys.exit('%s must be run as root' % sys.argv[0])

    

    for vm in VmNodeList.os_collect():
        print vm

    print_devices()

