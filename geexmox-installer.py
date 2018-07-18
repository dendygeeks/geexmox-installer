#!/usr/bin/python
import sys
import os
import csv
import subprocess
import StringIO
import re

ROOT_EUID = 0

class CpuVendor:
    INTEL = 'intel'
    OTHER = 'other'

    MAPPING = {'GenuineIntel': INTEL}
    
    @classmethod
    def read(cls):
        with open('/proc/cpuinfo') as f:
            for line in f:
                if 'vendor_id' in line:
                    vendor_name = line.split(':', 1)[1].strip()
                    return cls.MAPPING.get(vendor_name, cls.OTHER)

class PciDevice:
    BRACKETS_HEX = re.compile(r'\s*(.*?)\s*\[([0-9a-f]+)\]$', re.IGNORECASE)

    USB_CONTROLLER = '0c03'
    VGA_CONTROLLER = '0300'

    def __init__(self, slot, class_name, class_id, vendor_name, vendor_id, device_name, device_id):
        self.slot, self.class_name, self.class_id, self.vendor_name, self.vendor_id, self.device_name, self.device_id = \
                slot, class_name, class_id, vendor_name, vendor_id, device_name, device_id
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
        return cls(dct['slot'], class_name, class_id.lower(), vendor_name, vendor_id.lower(), device_name, device_id.lower()) 

    def __str__(self):
        subst = dict(self.__dict__)
        subst['class_str'] = ('%(class_name)s (%(class_id)s)' % self.__dict__).ljust(40)
        if self.device_name.lower() == 'device':
            subst['device_name'] = ''

        return '%(slot)s [%(vendor_id)s:%(device_id)s] %(class_str)s %(vendor_name)s %(device_name)s' % subst

class PciDeviceList:
    class LspciDialect(csv.excel):
        delimiter = ' '

    @classmethod
    def get(cls):
        csv.register_dialect('lspci', cls.LspciDialect)
        pci = subprocess.check_output(['lspci', '-mm', '-nn'])
        buf = StringIO.StringIO(pci)
        pci_header = 'slot class vendor device rev svendor sdevice'.split()
        reader = csv.DictReader(buf, fieldnames=pci_header, dialect='lspci')
        for item in reader:
            yield PciDevice.parse_pci_dict(item)
        csv.unregister_dialect('lspci')


if __name__ == '__main__':
    if CpuVendor.read() != CpuVendor.INTEL:
        sys.stderr.write('Non-Intel CPUs not fully supported by GeexMox. Pull requests are welcome! :)\n')

    if os.geteuid() != ROOT_EUID:
        sys.exit('%s must be run as root' % sys.argv[0])

    
    for dev in PciDeviceList.get():
        if dev.is_function:
            continue
        print dev
