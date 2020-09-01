#!/usr/bin/python
import sys
import os
import csv
import subprocess
import StringIO
import re
import pprint
import shlex
import urllib
import contextlib
import traceback
import glob
import collections
import copy
import stat

ROOT_EUID = 0

# Console ESC flags
BOLD = '\x1b[1m'
DIMMED = '\x1b[2m'

# Console ESC colors
RED_COLOR = '\x1b[31m'
LIGHT_RED_COLOR = '\x1b[91m'
YELLOW_COLOR = '\x1b[93m'
GREEN_COLOR = '\x1b[92m'

# Reset all console ESC flags
RESET_ALL = '\x1b[0m'

#APT_CONFIGS = [
#    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/preferences.d/geexmox',
#     '/etc/apt/preferences.d/geexmox'),
#    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/sources.list.d/geexmox.list',
#     '/etc/apt/sources.list.d/geexmox.list')
#]

MAX_PASSTHROUGH = 4

class ElephantArt:
    # unpacks mascot ASCII art from embedded text;
    # for more see decoration/html2ascii.py
    DATA = '''
    tar
    QlpoOTFBWSZTWcxvvLEAA13//9+5+OTLV/eeXBgQQf+hHgQIcXAABAASTABAAASH////0AYesx4qRc6OtQ4DdnQGmiENAU2qej1IxAabUxAADEAAA9QAD1MT
    Jk9EDU8mkTUoNHpAHqaaADIAANAAAAAAAANDjQ0aNBo0DQAAAAAMgAAADQGQAGDT0iSmFPRHqGgbUAPUGgAAAAAAAAAAASEiCCaoeTU9QzKaemoaAAAPUAAG
    QAAAB6ntKc2/y9XCyBeFgJJcT63HhyMrZngJK50g9/xj3uU8Tp+ZBShw1dLBSBR64R8U8ZCKoUQtkgH1GaEDExkYwc8XwiAJAnVghDKbGdCiVGXDDzkM+EMv
    CIGBSmzbNSoVJoKI3rJgSLRnhgxiaydPY3zDs8hqwzS+jokHZRI2468U7JW6JzvmZmFpBg2A22gG443eJKPpa4RiKGZVCmCI5N9rY++q11kyNMccGZscVUSo
    nURBra6GWY2kCANuJJ4ndTiwgX9JuVWq4dOzsKQBNppU6lVLQJU7ph00U5ASAECBJis5myGQCA0mes/HnNLHGZDLEK4vivAKCmpZw0uMQ2h2iBatV5Q2Nhdr
    T4Ok4NfgUh4Zx6O9v4M0zNO1mn+AVCBZwEBBbS3nVCvY7pWRtqPtdm5p7rxZhmwNLBvQxRgpG4KmsyobpV23u7LlNDa14xDaVDE2RobQ2dPqQI7c4ZdFoIWF
    GEwZLp0g6LEq9fvibQIQxoGpdEKgFCBJYBQwJpyJSQhAKAxRBEiAHews0zYsREYiGRFmG/NEOC8iuwZ7daoU0E7dwK3iF2kmwTtFs79CPZ4PVaK9HlNLKnKC
    ZDrELycxhaQufoWs+RRAMXlihLFmCtw66mRMzSkps1oRIshXW56lJhWZGUVkMxUyrK5ZHCwF93EqpCAwmMIdJeAJkO2Cbg5V64ErFCBO9/X32t3RUbOym7t/
    wTRXcef7096qG9LjiFZUp3tDHa2jesXT39PHHf/1tkJudIz7rnOmy4cKnLknVuzC5Y3Pjl2T0WKOvRwKK7z3GpRbcXWXTy5D65nrGuq+HhAmcORg4+eMDKHk
    PRSpcCSGDciyiYimxFNBGWrTlvQqThwgyy7PMAR0FSAg6VUcFmSGCOHXwza9MUnNVKuagU1VStF6EOMpfBiRFScRgXdMV1UiSFiNTayrabMwaJBEuLpCWhIr
    9WjFibEmHYh+qPGaCSk6qbKxkEM95DKgJSRxvUWq8Yasm3aUTMMDGzIwhki8TE4XcOTSDSLEXlitVVI1gBm01dRBlK1lEhm6sdbghBIdYIpBDBwUXmCCVN2F
    MoCpZDNFVSGk5iszESEwVDgWNGWaURoiKIkEOIGLxxitjJeS8xYNjhMKd2ViNGAxFMLOzCzwqZ5QpqzSWTpqDC1Va6GwDJgderl6SP91rHIk05VTLWbHocrX
    pgsGWvFoZcxsFGTVpAs0qMahV4LB4lSXoxtYxjGqdU4WZoSEvzYG3sKVR6yKCfyuxRYa3RCujG2B2cBZfr0ZZNA1z55r59RoRoM8hZgw+3Iy936hZo+I0I3D
    7Do59yUbTc2NA2xJoWwPu5t42v9uyG+MWIZROSV2muGUoAXYJUbg287NvDNySgigiASUv6Gs0BIeQEJUSlQJCI0GgThvIKJIIJh0NMbXDDhqhxgUDUWt2ajB
    Ngm02mJJgAw7TQ9j6jj4XZbzbJfhc1unWqGLDCsmroiQQIICSMVjXjM8+agIzfwVkn8nNtP8CmmNsnOOcT0YQLIp5cfPL54lKi0jZdo7thzaypWgccLTXLOh
    3j5ItzkyL2IHPEQpwWFOXsPrQLkTdNxCgWcC8SzqIuPX3u2G3i4KYyqKcLOVv3IjowIBTbEdXrsGDEL/xdyRThQkMxvvLEA=
    '''

    ANSI_ESC_COLOR = '\x1b[40;38;5;%dm%s'
    ANSI_RESET_COLOR = '\x1b[0m'
    
    @classmethod
    def get_mascot(cls):
        image = cls.unpack_mascot()
        try:
            terminal_width = int(subprocess.check_output(['tput', 'cols']).strip()) - 1
        except (subprocess.CalledProcessError, ValueError):
            pass
        else:
            text_width = sum(len(text) for (color, text) in image[0])
            if text_width > terminal_width:
                strip_left = int(text_width - terminal_width) / 2
                strip_right = text_width - terminal_width - strip_left
                stripped = []
                for row in image:
                    remain = strip_left
                    while row and remain > 0:
                        if len(row[0][1]) < remain:
                            remain -= len(row[0][1])
                            del row[0]
                        else:
                            row[0] = (row[0][0], row[0][1][remain:])
                            break
                    remain = strip_right
                    while row and remain > 0:
                        if len(row[-1][1]) < remain:
                            remain -= len(row[-1][1])
                            del row[-1]
                        else:
                            row[-1] = (row[-1][0], row[-1][1][:-remain])
                            break
                    stripped.append(row)
                image = stripped
        
        result = []
        for img_row in image:
            row = []
            for color, text in img_row:
                row.append(cls.ANSI_ESC_COLOR % (color, text))
            result.append(''.join(row))
        result.append(cls.ANSI_RESET_COLOR)

        return '\n'.join(result)


    @classmethod
    def unpack_mascot(cls):
        import base64
        import zipfile
        import tarfile
        import struct
        import StringIO

        lines = [line.strip() for line in cls.DATA.splitlines() if line.strip()]
        if lines[0].lower() not in ('zip', 'tar'):
            raise ValueError('Unsupported format')
        use_zip = lines[0].lower() == 'zip'
        buf = StringIO.StringIO(base64.b64decode(''.join(lines[1:])))
        
        if use_zip:
            with zipfile.ZipFile(buf, 'r') as zf:
                data = zf.open('ascii-ansi.bin').read()
        else:
            with tarfile.open(fileobj=buf) as tf:
                data = tf.extractfile('ascii-ansi.bin').read()

        image = []
        for line in data.splitlines():
            row, offset = [], 0
            line = line.strip()
            while offset < len(line):
                fmt = '<Bb'
                color, size = struct.unpack_from(fmt, line, offset)
                offset += struct.calcsize(fmt)
                fmt = '<%ds' % (1 if size < 0 else size)
                text, = struct.unpack_from(fmt, line, offset)
                offset += struct.calcsize(fmt)
                if size < 0:
                    text = text[0] * (-size)
                row.append((color, text))
            image.append(row)
        return image

class PrintEscControl:
    current = [RESET_ALL]
    
    @classmethod
    def __switch_color(cls):
        color = ''.join(cls.current)
        for handle in (sys.stdout, sys.stderr):
            handle.write(color)
            handle.flush()

    def __init__(self, begin_seq):
        self.begin_seq = begin_seq

    def __enter__(self, *a, **kw):
        self.current.append(self.begin_seq)
        self.__switch_color()

    def __exit__(self, *a, **kw):
        prev_color = self.current.pop()
        assert prev_color == self.begin_seq
        self.__switch_color()

class CalledProcessError(subprocess.CalledProcessError):
    def __init__(self, returncode, cmd, output=None, errout=None):
        subprocess.CalledProcessError.__init__(self, returncode, cmd, output)
        self.errout = errout

    def __str__(self):
        if self.returncode != 0:
            return subprocess.CalledProcessError.__str__(self)
        return 'Command "%s" reported error:\n%s' % (subprocess.list2cmdline(self.cmd), self.errout or 'unknown')
    def __repr__(self):
        if self.returncode != 0:
            return subprocess.CalledProcessError.__repr__(self)
        return 'Command "%s" reported error:\n%s' % (subprocess.list2cmdline(self.cmd), self.errout or 'unknown')

def call_cmd(cmd, need_output=True, need_empty_stderr=True):
    with PrintEscControl(DIMMED):
        if not need_output:
            print '$ %s' % subprocess.list2cmdline(cmd)
        proc = subprocess.Popen(cmd,
                stdout=subprocess.PIPE if need_output else None,
                stderr=subprocess.PIPE if need_output else None)
        proc.wait()
        out, err = proc.communicate()
        if proc.returncode != 0 or (need_output and need_empty_stderr and err.strip()):
            raise CalledProcessError(proc.returncode, cmd, out, err)
        return out

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

    VFIO_DRIVER = 'vfio-pci'

    def __init__(self, slot, class_name, class_id, vendor_name, vendor_id, device_name, device_id, driver, module):
        self.slot, self.class_name, self.class_id = slot, class_name, class_id
        self.vendor_name, self.vendor_id = vendor_name, vendor_id
        self.device_name, self.device_id = device_name, device_id
        self.driver, self.module = driver, module
        self.full_slot = slot

        if slot.endswith('.0'):
            self.is_function = False
            #self.slot = slot[:-2]
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

    def is_same_addr(self, slot):
        return self.full_slot.startswith(slot)

    def can_passthru(self):
        return bool(self.module)

    def is_driven_by_vfio(self):
        return self.driver == self.VFIO_DRIVER

class PciDeviceList:
    _cache = None

    class LspciDialect(csv.excel):
        delimiter = ' '

    @classmethod
    def _os_collect(cls):
        pci = call_cmd(['lspci', '-k', '-nn', '-vmm'])
        item = {}
        for line in pci.splitlines():
            line = line.strip()
            if not line:
                if item:
                    yield PciDevice.parse_pci_dict(item)
                item = {}
                continue
            key, value = line.split(':', 1)
            item[key.strip().lower()] = (item.get(key.strip().lower(), '') + ' ' + value.strip()).strip()

        if item:
            yield PciDevice.parse_pci_dict(item)

    @classmethod
    def os_collect(cls):
        if not cls._cache:
            cls._cache = list(cls._os_collect())
        for item in cls._cache:
            yield item

    @classmethod
    def get_functions(cls, device):
        slot_no_function = device.slot.split('.')[0]
        result = []
        for dev in cls.os_collect():
            if dev.is_function and dev.is_same_addr(slot_no_function):
                result.append(dev)
        return result

class QemuConfig:
    ValidateResult = collections.namedtuple('ValidateResult', 'problem solution have_to_stop')

    class QemuConfigEntry:
        def __init__(self, value):
            self.value = value.split(',')
        def __str__(self):
            return str(self.value)
        def __repr__(self):
            return repr(self.value)

    class QemuConfigArgs(QemuConfigEntry):
        def __init__(self, value):
            self.value = shlex.split(value)

    class QemuConfigDescription(QemuConfigEntry):
        def __init__(self, value):
            self.value = urllib.unquote(value)

    class QemuSubvalueWrapper:
        def __init__(self):
            self.__dict = {}
            self.value = self
        def __setitem__(self, key, value):
            self.__dict[key] = value
        def __getitem__(self, key):
            return self.__dict[key].value
        def __delitem__(self, key):
            del self.__dict[key]
        def get(self, key, default=None):
            try:
                result = self.__dict[key]
            except KeyError:
                return default
            return result.value
        def items(self):
            for key, value in self.__dict.items():
                yield key, value.value
        def __len__(self):
            return len(self.__dict)

    QEMU_CONFIG_NAME_TO_VALUE = {
        'args': QemuConfigArgs,
        'description': QemuConfigDescription,
    }
    
    ENDING_DIGITS = re.compile(r'^(.*)(\d+)$')
    PCI_SLOT_ADDR = re.compile(r'^\d+(:\d+(\.\d+)?)?')

    def __init__(self, vmid):
        self.vmid = vmid
        self.__config = {}

    @property
    def empty(self):
        return not self.__config
    
    def parse_line(self, line):
        key, value = line.split(':', 1)
        key = key.strip().lower()
        line_class = self.QEMU_CONFIG_NAME_TO_VALUE.get(key, self.QemuConfigEntry)
        value = line_class(value.strip()) 

        if self.ENDING_DIGITS.match(key):
            key, number = self.ENDING_DIGITS.match(key).groups()
            self.__config.setdefault(key, self.QemuSubvalueWrapper())[number] = value
        else:
            self.__config[key] = value
    
    def __getitem__(self, name):
        return self.__config[name].value
    def __setitem__(self, name, value):
        self.__config[name] = value

    def get(self, name, default=None):
        try:
            result = self.__config[name]
        except KeyError:
            return default
        return result.value

    @classmethod
    def translate_hostpci_to_devices(cls, hostpci_entry):
        for item in hostpci_entry:
            if cls.PCI_SLOT_ADDR.match(item):
                for dev in PciDeviceList.os_collect():
                    if dev.is_same_addr(item):
                        yield dev

    def get_hostpci_devices(self):
        for _, passthru_cfg in self.get('hostpci', {}).items():
            for dev in self.translate_hostpci_to_devices(passthru_cfg):
                yield dev

    def validate(self):
        # check that OVMF bios has EFI disk
        issues = []
        if self.get('bios', [None])[0] == 'ovmf':
            if not self.get('efidisk', {}).get('0', None):
                issues.append(self.ValidateResult(
                        problem='Missing EFI disk with OVMF bios selected',
                        solution='Please add EFI disk using ProxMox Hardware menu',
                        have_to_stop=True))

        # check that if we're passing something thru we use OVMF and don't use ballooning
        if self.get('hostpci'):
            if self.get('bios', [None])[0] != 'ovmf':
                issues.append(self.ValidateResult(
                        problem='Passing throught devices on non-OVMF bios is unsupported',
                        solution='Switch BIOS to OVMF using ProxMox Options menu or do not pass PCI devices to it',
                        have_to_stop=True))
            if 'q35' not in self.get('machine', [''])[0]:
                issues.append(self.ValidateResult(
                        problem='Passing through devices on OVMF requires machine to be q35-descendant',
                        solution='Please fix qemu config for %s vmid' % self.vmid,
                        have_to_stop=True))
            if self.get('balloon', [None])[0] != '0':
                issues.append(self.ValidateResult(
                        problem='Cannot enable memory ballooning when passing through PCI devices',
                        solution='Disable memory ballooning using ProxMox Hardware menu or do not pass PCI devices to it',
                        have_to_stop=True))
            if len(self['hostpci']) > MAX_PASSTHROUGH:
                issues.append(self.ValidateResult(
                        problem='Cannot have more than %d PCI devices passed through' % MAX_PASSTHROUGH,
                        solution='Pass fewer PCI devices',
                        have_to_stop=False))
            nums = [int(number) for number, _ in self['hostpci'].items()]
            if min(nums) < 0 or max(nums) >= MAX_PASSTHROUGH:
                issues.append(self.ValidateResult(
                        problem='Cannot have hostpci number < 0 or >= %d' % MAX_PASSTHROUGH,
                        solution='Please fix qemu config for %s vmid' % self.vmid,
                        have_to_stop=True))

        # check that PCI passed through are driven by vfio
        for dev in self.get_hostpci_devices():
            if not dev.can_passthru():
                issues.append(self.ValidateResult(
                        problem='Cannot pass through device at %s: not driven by a kernel module' % dev.slot,
                        solution='Run "%s --reconf", select correct devices and reboot OR do bot pass this device through' % os.path.basename(sys.argv[0]),
                        have_to_stop=False))
            if not dev.is_driven_by_vfio():
                issues.append(self.ValidateResult(
                        problem='Bad driver for device at %s, should be %s for passing through' % (dev.slot, PciDevice.VFIO_DRIVER),
                        solution='Run "%s --reconf", select correct devices and reboot OR do not pass this device through' % os.path.basename(sys.argv[0]),
                        have_to_stop=False))

        # check that if '-cpu' is present in 'args' it matches global 'cpu'
        if self.get('args') and self.get('cpu'):
            cpu_index = self['args'].index('-cpu')
            if cpu_index > 0 and self.get('cpu'):
                if cpu_index + 1 >= len(self['args']):
                    issues.append(self.ValidateResult(
                            problem='No cpu value present for -cpu argument: %s' % self['args'],
                            solution='Please fix qemu config for %s vmid' % self.vmid,
                            have_to_stop=True))
                if self['args'][cpu_index + 1].split(',')[0] != self['cpu'][0]:
                    issues.append(self.ValidateResult(
                            problem='CPU type in args differs from global CPU type',
                            solution='Please select matching CPU type or fix -cpu argument',
                            have_to_stop=True))

        return issues

class VmNode:
    STOPPED = 'stopped'
    RUNNING = 'running'

    def __init__(self, vmid, name, status, mem, bootdisk, pid):
        self.vmid, self.name, self.status, self.mem, self.bootdisk, self.pid = \
                vmid, name, status, mem, bootdisk, pid
        self.config = QemuConfig(vmid)
    
    @classmethod
    def parse_qmlist_dict(cls, dct):
        return cls(dct['VMID'], dct['NAME'], dct['STATUS'], dct['MEM(MB)'], dct['BOOTDISK(GB)'], dct['PID']) 

    def __str__(self):
        subst = dict(self.__dict__)
        return '%(vmid)s %(name)s %(status)s %(mem)s %(bootdisk)s %(pid)s' % subst

    def parse_config(self):
        print '%s config for "%s"...' % ('Getting' if self.config.empty else 'Refreshing', self.name)
        self.config = QemuConfig(self.vmid)
        lines = call_cmd(['qm', 'config', str(self.vmid)]).splitlines()
        for line in lines:
            self.config.parse_line(line)

class VmNodeList:
    class QmDialect(csv.excel):
        delimiter = ' '
        skipinitialspace=True
    
    @classmethod
    def os_collect(cls):
        print 'Getting list of VMs...'
        qm = call_cmd(['qm', 'list'])
        buf = StringIO.StringIO(qm)
        
        csv.register_dialect('qm', cls.QmDialect)
        reader = csv.DictReader(buf, dialect='qm')
        csv.unregister_dialect('qm')

        for item in reader:
            yield VmNode.parse_qmlist_dict(item)

def print_devices(enabler, show_disabled=True):
    printed_devs = []
    def perform_grouping(label, predicate):
        title_shown = False
        
        for dev in PciDeviceList.os_collect():
            if not predicate(dev):
                continue
            if enabler(dev):
                printed_devs.append(dev)
                if not title_shown:
                    with PrintEscControl(BOLD):
                        print label
                    title_shown = True
                print "%2d. %s" % (len(printed_devs), dev)
            elif show_disabled:
                if not title_shown:
                    with PrintEscControl(BOLD):
                        print label
                    title_shown = True
                with PrintEscControl(RED_COLOR):
                    print '    %s' % dev
    
        if title_shown:
            print

    perform_grouping("VGA CONTROLLERS (videocards)",
            lambda dev: dev.class_id == PciDevice.VGA_CONTROLLER)
    perform_grouping("USB CONTROLLERS",
            lambda dev: dev.class_id == PciDevice.USB_CONTROLLER)
    perform_grouping("OTHER DEVICES",
            lambda dev: dev.class_id not in (PciDevice.USB_CONTROLLER, PciDevice.VGA_CONTROLLER))
    
    return printed_devs

def download_internal(url, target):
    print 'Downloading %s as %s' % (url, target)
    try:
        with contextlib.closing(urllib.urlopen(url)) as page:
            with open(target, 'wb') as f:
                f.write(page.read())
    except IOError:
        raise IOError("Can't download the file %s as %s" % (url, target))

def download_wget(url, target):
    print 'Downloading %s as %s' % (url, target)
    try:
        call_cmd(['wget', url, '-O', target], need_output=False)
    except subprocess.CalledProcessError:
        raise IOError("Can't download the file %s as %s" % (url, target))

def print_title(msg):
    with PrintEscControl(BOLD):
        print '%s\n%s\n' % (msg, '=' * len(msg.strip()))


def prompt_yesno(msg, default_answer=True):
    prompt = '%s? [%s] ' % (msg, 'Y/n' if default_answer else 'y/N')
    with PrintEscControl(BOLD):
        while True:
            ans = raw_input(prompt).strip().lower()
            if not ans:
                return default_answer
            if ans in ('y', 'yes'):
                return True
            if ans in ('n', 'no'):
                return False

class IncorrectInputException(Exception):
    def __init__(self, msg):
        self.msg = msg

def prompt_predicate(msg, predicate):
    with PrintEscControl(BOLD):
        while True:
            try:
                result = predicate(raw_input(msg))
            except IncorrectInputException as err:
                with PrintEscControl(RED_COLOR):
                    print err.msg
                continue
            return result

def prompt_comma_list(msg, min_val, max_val):
    def parse_comma_list(ans):
        try:
            ans = ans.strip().split(',')
            result = [int(e.strip()) for e in ans if e.strip()]
            for e in result:
                if e < min_val or e > max_val:
                    raise ValueError()
        except ValueError:
            raise IncorrectInputException(
                    'Incorrect input: enter comma-separated list of values from %s to %s\n' % (min_val, max_val))
        return result
    return prompt_predicate(msg, parse_comma_list)

def prompt_int(msg, min_val, max_val):
    def parse_int(ans):
        try:
            result = int(ans.strip())
            if result < min_val or result > max_val:
                raise ValueError()
        except ValueError:
            raise IncorrectInputException(
                    'Incorrect input: enter integer value from %s to %s\n' % (min_val, max_val))
        return result
    return prompt_predicate(msg, parse_int)

def get_module_depends(modname):
    try:
        modinfo = subprocess.check_output(['modinfo', modname], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        if ('%s not found' % modname) in err.output:
            return []
        sys.stderr.write(err.output)
        raise

    for line in modinfo.splitlines():
        if line.split(':')[0] == 'depends':
            depends = line.split(':', 1)[1].strip()
            return depends.split(',') if depends else []
    return []

def inject_geexmox_overrides():
    sbin_command = '/usr/local/sbin/geexmox'
    if os.path.abspath(__file__) != sbin_command:
        print '\nInstalling "%s" command...' % sbin_command
        if os.path.exists(sbin_command) or os.path.lexists(sbin_command):
            os.unlink(sbin_command)

        os.symlink(os.path.abspath(__file__), sbin_command)
        stats = os.stat(os.path.abspath(__file__))
        os.chmod(os.path.abspath(__file__), stats.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    with open(__file__, 'rb') as myself:
        content = myself.read()
    if '\r' in content:
        with open(__file__, 'wb') as myself:
            myself.write(content.replace('\r', ''))

    print '\nMaking sure apt has https transport...'
    call_cmd(['apt-get', 'install', '-y', 'apt-transport-https'], need_output=False)

    os.chdir('geexmox-pve-overrides')
    packages_found = False
    if os.path.isdir("apt-repo/result"):
        for file in os.listdir("apt-repo/result"):
            if file.endswith(".deb"):
                packages_found = True
                print "Package found: " + file
    if not packages_found:
        raise Exception("You have to compile the PVE overrides first.\nGo to the geexmox-pve-overrides directory and run make as an ordinary user and then restart geexmox-installer.py")
    #os.chdir("..")

    #call_cmd(['bash', 'prepare.sh'], need_output=False)
    #call_cmd(['make'], need_output=False)
    print 'Installing the newly built packages over the default PVE ones...'
    os.chdir('apt-repo')
    call_cmd(['bash', 'update-debs.sh'], need_output=False)
    call_cmd(['bash', 'add-apt-repos.sh'], need_output=False)
    os.chdir('result')
    call_cmd(['bash', '-c', 'dpkg -i *.deb'], need_output=False)
    #package_name = call_cmd(['bash', '-c', 'ls *kernel*geexmox*.deb'])
    #version_search = re.search('pve-kernel-(.*-pve-geexmox)*', package_name)
    #if version_search:
    #    version = version_search.group(1)
    #    print 'Setting the default boot kernel to ' + str(version)
    #    menuentry_line = call_cmd(['bash', '-c', 'grep "$menuentry_id_option" /boot/grub/grub.cfg | ' + 'grep "' + version + '"']) 
    #    menuentry_id_search=re.search("\$menuentry_id_option ('.*')", menuentry_line)
    #    menuentry_id = menuentry_id_search.group(1)
    #    print 'GRUB menuentry id option is ' + menuentry_id

        #call_cmd(['grub-set-default', str(index)])

    grub_text = []
    update_grub_config = False
    with open('/etc/grub.d/10_linux') as grub_conf:
        for line in grub_conf:
            if "vmlinuz-* " in line:
                line = line.replace("vmlinuz-*", "vmlinuz-*-geexmox")
                update_grub_config=True
            elif "vmlinux-* " in line:
                line = line.replace("vmlinux-*", "vmlinux-*-geexmox")
                update_grub_config=True
            grub_text.append(line)

    print 'Patching grub updater to ignore all kernels except geexmox...'
    with open('/etc/grub.d/10_linux', 'w') as grub_conf:
        grub_conf.write(''.join(grub_text))
    call_cmd(['update-grub'], need_output=False)


#    if no_enterprise:
#        disable_pve_enterprise(verbose=False)


#    for url, target in APT_CONFIGS:
#        download(url, target)

def disable_pve_enterprise(verbose=True):
    logos = [
        ('bootsplash_dg.jpg', '/usr/share/qemu-server/bootsplash.jpg'),
        ('logo-128_dg.png', '/usr/share/pve-manager/images/logo-128.png'),
        ('proxmox_logo_dg.png', '/usr/share/pve-manager/images/proxmox_logo.png'),
    ]
    logo_start_url = 'https://dendygeeks.github.io/geexmox-pve-overrides/logos/'

    for fname in glob.glob('/etc/apt/sources.list.d/*'):
        with open(fname) as conf:
            contents = conf.read().splitlines()
        remove = False
        for idx, line in enumerate(contents):
            nocomment = line.split('#')[0].strip()
            if 'https://enterprise.proxmox.com/debian/pve' in nocomment and 'pve-enterprise' in nocomment:
                remove = True
                contents[idx] = '# removed by %s: # %s' % (os.path.basename(sys.argv[0]), line)
        if remove:
            if verbose:
                print 'Removing PVE Enterprise apt repo at %s...' % fname
            with open(fname, 'w') as conf:
                conf.write('\n'.join(contents))

    libjs = r'/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js'
    if os.path.exists(libjs):
        if verbose:
            print 'Patching %s to remove nag...' % libjs
        with open(libjs) as jsfile:
            text = jsfile.read().splitlines()
        for idx, line in enumerate(text):
            if line.strip() == "if (data.status !== 'Active') {":
                text[idx] = line.replace("data.status !== 'Active'", "false")
                patched = True
                break
        else:
            patched = False
            if verbose:
                with PrintEscControl(YELLOW_COLOR):
                    print 'Cannot find the nag, maybe already patched'
        if patched:
            with open(libjs, 'w') as jsfile:
                jsfile.write('\n'.join(text))
            if verbose:
                print 'Patched out the nag'

    for logo_name, logo_target in logos:
        if os.path.exists(logo_target):
            download(logo_start_url + logo_name, logo_target)

ADDRESS_RE = re.compile(r'\s*inet\s+(\d+\.\d+\.\d+\.\d+).*scope\s+global.*')
def install_proxmox():
    # installing ProxMox by following official guide:
    # https://pve.proxmox.com/wiki/Install_Proxmox_VE_on_Debian_Stretch
    hostname = subprocess.check_output(['hostname']).strip()
    hostname_ip = subprocess.check_output(['hostname', '--ip-address']).strip()
    
    ip_config = subprocess.check_output(['ip', 'address']).strip()
    real_ip = None
    patch_hosts = False
    for line in ip_config.splitlines():
        match = ADDRESS_RE.match(line)
        if match:
            if match.group(1) == hostname_ip:
                break
            if real_ip is None:
                real_ip = match.group(1)
    else:
        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '"hostname --ip-address"  is not assigned to any valid network interface'
        if real_ip is not None:
            if prompt_yesno('Assign "%s" as "%s" address instead' % (real_ip, hostname)):
                hostname_ip = real_ip
                patch_hosts = True

    if not patch_hosts:
        with open('/etc/hosts') as hosts:
            for line in hosts:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                if line.split()[0] == hostname_ip:
                    print 'Current host %(b)s%(h)s%(r)s ip address %(b)s%(ip)s%(r)s is present in /etc/hosts' % \
                            {'b': BOLD, 'r': RESET_ALL, 'h': hostname, 'ip': hostname_ip}
                    break
            else:
                patch_hosts = True

    if patch_hosts:
        print 'Current host %(b)s%(h)s%(r)s ip address %(b)s%(ip)s%(r)s not present in /etc/hosts' % \
                {'b': BOLD, 'r': RESET_ALL, 'h': hostname, 'ip': hostname_ip}
        print 'It should be there for ProxMox installation to succeed.'
        if prompt_yesno('Add %s entry to /etc/hosts' % hostname):
            with open('/etc/hosts') as hosts:
                lines = hosts.readlines()
            with open('/etc/hosts', 'w') as hosts:
                for line in lines:
                    no_comment = line.split('#')[0].strip()
                    if not no_comment:
                        continue
                    if re.search(r'\s+%s(\s+|$)' % re.escape(hostname), no_comment):
                        hosts.write('#%(line)s # automagically commented by %(prog)s\n' % 
                                {'line': line.rstrip(), 'prog': os.path.basename(sys.argv[0])})
                    else:
                        hosts.write(line)
                hosts.write('\n%(ip)s\t%(host)s\t\t# automagically added by %(prog)s\n' %
                        {'ip': hostname_ip, 'host': hostname, 'prog': os.path.basename(sys.argv[0])})

    print 'Adding ProxMox repo and key...'
    with open('/etc/apt/sources.list.d/pve-install-repo.list', 'w') as pve:
        pve.write('deb [arch=amd64] http://download.proxmox.com/debian/pve buster pve-no-subscription\n')
    download('http://download.proxmox.com/debian/proxmox-ve-release-6.x.gpg',
            '/etc/apt/trusted.gpg.d/proxmox-ve-release-6.x.gpg')
    
    no_enterprise = prompt_yesno('Remove PVE Enterprise configs and nag warnings', default_answer=False)
    if no_enterprise:
        disable_pve_enterprise()

    print '\nUpdating apt db...'
    call_cmd(['apt-get', 'update'], need_output=False)
    print
    if prompt_yesno('ProxMox recommends dist-upgrade, perform now'):
        print 'Upgrading distribution...'
        call_cmd(['apt-get', 'dist-upgrade', '-y', '--allow-unauthenticated', '--allow-downgrades'], need_output=False)

    print '\nInstalling ProxMox...'
    call_cmd(['apt-get', 'install', '-y', '--allow-unauthenticated', '--allow-downgrades', 'proxmox-ve', 'open-iscsi'], need_output=False)
    print
    if prompt_yesno('ProxMox recommends installing postfix, install', default_answer=False):
        call_cmd(['apt-get', 'install', '-y', 'postfix'], need_output=False)
    print


def ensure_vfio(devices):
    need_update_initramfs = False
    print 'Ensuring VFIO drivers are enabled'
    vfio_drivers = {key: False for key in 'vfio vfio_iommu_type1 vfio_pci vfio_virqfd'.split()}
    with open('/etc/modules') as modules:
        for line in modules:
            line = line.split('#')[0].strip()
            if not line:
                continue
            if line in vfio_drivers:
                vfio_drivers[line] = True
    if not all(vfio_drivers.values()):
        with open('/etc/modules', 'a+') as modules:
            modules.write('# automagically added by %s\n' % os.path.basename(sys.argv[0]))
            for driver, is_present in vfio_drivers.items():
                if not is_present:
                    need_update_initramfs = True
                    modules.write('%s\n' % driver)

    modprobe_cfg = [
            ('options vfio_iommu_type1', 'allow_unsafe_interrupts=1'),
            ('options kvm', 'ignore_msrs=Y'),
    ]
    device_modules = set()
    device_ids = []
    vfio_modules = set([PciDevice.VFIO_DRIVER] + get_module_depends(PciDevice.VFIO_DRIVER))

    modules_to_walk = set()
    for dev in devices:
        for module in dev.module.split():
            if module not in vfio_modules:
                modules_to_walk.add(module)
        device_ids.append('%s:%s' % (dev.vendor_id, dev.device_id))

    while modules_to_walk:
        device_modules |= modules_to_walk
        next_modules = set()
        for module in modules_to_walk:
            next_modules |= set(get_module_depends(module))
        modules_to_walk = next_modules - device_modules
    device_modules = [module.strip() for module in sorted(device_modules)]

    modprobe_cfg.append(('softdep vfio-pci', ' '.join(['post:'] + device_modules)))
    for module in device_modules:
        modprobe_cfg.append(('softdep %s' % module, 'pre: vfio-pci'))
    modprobe_cfg.append(('options vfio-pci', 'ids=%s' % ','.join(sorted(set(device_ids)))))

    not_found = []
    for starter, value in modprobe_cfg:
        found_starter = False
        for fname in glob.glob('/etc/modprobe.d/*.conf'):
            content, do_patch = [], False 
            with open(fname) as f:
                for line in f:
                    no_comment = line.split('#')[0].strip()
                    if no_comment.startswith(starter + ' '):
                        if no_comment[len(starter):].strip() != value:
                            with PrintEscControl(YELLOW_COLOR):
                                print 'Commenting out "%s" in %s' % (line.strip(), fname)
                            do_patch = True
                            need_update_initramfs = True
                            content.append('# %s #-- commented by %s' % (line.rstrip(), os.path.basename(sys.argv[0])))
                            continue
                        print 'Required "%s %s" present in %s' % (starter, value, fname)
                        found_starter = True
                    content.append(line.rstrip())
            if do_patch:
                with open(fname, 'w') as f:
                    f.write('\n'.join(content) + '\n')
        if not found_starter:
            not_found.append((starter, value))

    if not_found:
        with open('/etc/modprobe.d/geexmox.conf', 'a+') as f:
            for starter, value in not_found:
                print 'Writing "%s %s" to geexmox.conf' % (starter, value)
                f.write('%s %s\n' % (starter, value))
        need_update_initramfs = True

    if need_update_initramfs:
        print '\nUpdating initramfs to apply vfio configuration...'
        call_cmd(['update-initramfs', '-u', '-k', 'all'], need_output=False)

IOMMU_ENABLING = {
    CpuVendor.INTEL: ['intel_iommu=on', 'video=efifb:off'],
}
GRUB_CMDLINE_RE = re.compile(r'(\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*")([^"]*)("\s*)')

def ensure_kernel_params_no_reboot(kernel_params):
    grub_text = []
    update_grub_config = False 
    with open('/etc/default/grub') as grub_conf:
        for line in grub_conf:
            no_comment = line.split('#')[0].strip()
            match = GRUB_CMDLINE_RE.match(no_comment)
            if match:
                args = shlex.split(match.group(2))
                for extra_arg in kernel_params:
                    if extra_arg not in args:
                        update_grub_config = True
                        args.append(extra_arg)
                line = GRUB_CMDLINE_RE.sub(r'\1%s\3' % subprocess.list2cmdline(args), line)
            grub_text.append(line)

    if update_grub_config:
        print 'Updating grub config...'
        with open('/etc/default/grub', 'w') as grub_conf:
            grub_conf.write(''.join(grub_text))
        call_cmd(['update-grub'], need_output=False)
    return not update_grub_config

def enable_iommu(devices):
    try:
        kernel_params = IOMMU_ENABLING[CpuVendor.os_collect()]
    except KeyError:
        with PrintEscControl(RED_COLOR):
            sys.stderr.write('%s does not know how to enable IOMMU on your CPU yet.\n' % os.path.basename(sys.argv[0]))
        return
    ensure_kernel_params_no_reboot(kernel_params)

def stage1():
    if CpuVendor.os_collect() != CpuVendor.INTEL:
        with PrintEscControl(YELLOW_COLOR):
           sys.stderr.write('Non-Intel CPUs are not fully supported by GeexMox. Pull requests are welcome! :)\n')

    install_proxmox()
    inject_geexmox_overrides()

    print_title('PCI devices present:')

    devices = print_devices(lambda dev: dev.can_passthru())

    while True:
        passthru = prompt_comma_list('Input comma-separated list of devices to enable passthrough for: ', 1, len(devices))
        if passthru:
            with PrintEscControl(BOLD):
                print '\nDevices selected for passing through:'
            for idx in passthru:
                print devices[idx - 1]
        else:
            with PrintEscControl(BOLD):
                print '\nNo devices selected for passing through'
        print
        if prompt_yesno('Is it correct'):
            break

    if passthru:
        pass_devices = [devices[idx - 1] for idx in passthru]
        for parent_device in list(pass_devices):
            pass_devices.extend(PciDeviceList.get_functions(parent_device))
        ensure_vfio(pass_devices)
        enable_iommu(pass_devices)

    with PrintEscControl(BOLD):
        print '\nTo continue with configuring VMs please reboot and re-run %s' % os.path.basename(sys.argv[0])

def check_iommu_groups(devices):
    iommu = {}
    for device_path in glob.glob('/sys/kernel/iommu_groups/*/devices/*'):
        group = device_path.split('/')[4]
        device_addr = device_path.split('/')[-1]
        if not device_addr.startswith('0000:'):
            with PrintEscControl(RED_COLOR):
                sys.stderr.write('Unsupported PCI configuration, more than one bus found')
        iommu[device_addr[5:]] = group

    group_devs = {}
    for dev in devices:
        group = iommu[dev.full_slot]
        group_devs.setdefault(group, []).append(dev)
    group_devs = {key: val for (key, val) in group_devs.items() if len(val) > 1}

    if group_devs:
        for group, devices in group_devs.items():
            with PrintEscControl(BOLD):
                print 'IOMMU group %s:' % group
            for dev in devices:
                print dev
        if prompt_yesno('Do you want to pass through devices from same group to different VMs'):
            if not ensure_kernel_params_no_reboot(['pcie_acs_override=downstream,multifunction']):
                with PrintEscControl(BOLD + YELLOW_COLOR):
                    print 'To continue with configuring VMs please reboot and re-run %s' % os.path.basename(sys.argv[0])
                    sys.exit(0)

def list_and_validate_vms():
    vms = list(VmNodeList.os_collect())
    print '\nValidating created VMs configurations...'
    for vm in vms:
        vm.parse_config()

    have_to_stop = False
    for vm in vms:
        issues = vm.config.validate()
        if not issues:
            continue
        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '\nWARNING: VM "%s" has configuration %s:' % (vm.name, 'issues' if len(issues) > 1 else 'issue')
        for issue in issues:
            with PrintEscControl(YELLOW_COLOR):
                print issue.problem + '.'
            with PrintEscControl(GREEN_COLOR):
                with PrintEscControl(BOLD):
                    print 'SOLUTION: ',
                print '%s.' % issue.solution
            have_to_stop = have_to_stop or issue.have_to_stop

    if have_to_stop:
        with PrintEscControl(BOLD):
            print '\nPlease fix issues above and refresh VM list to continue configuring'
            return []

    return vms

def show_passthrough_devs(vm):
    if vm.config.get('hostpci'):
        print_title('\nPCI devices already passed through:')
        for dev in vm.config.get_hostpci_devices():
            print dev
    else:
        print 'Currently no PCI devices are passed through'

def choose_devs_for_passthrough(vm):
    show_passthrough_devs(vm)
    print_title('\nPCI devices available for passthrough:')

    devices = print_devices(lambda dev: dev.is_driven_by_vfio(), False)
    passthru = prompt_comma_list('Input comma-separated list of devices to passthrough in "%s" (0 - go back): ' % vm.name, 0, len(devices))
    if 0 in passthru:
        return [], vm.config

    passthru = [devices[idx - 1] for idx in passthru]

    removed = {}
    number_keep, added = set(), list(passthru)

    for number, passthru_cfg in vm.config.get('hostpci', {}).items():
        for old_dev in vm.config.translate_hostpci_to_devices(passthru_cfg):
            for dev in passthru:
                if dev.is_same_addr(old_dev.slot):
                    added.remove(dev)
                    number_keep.add(number)
                    break
            else:
                removed[number] = old_dev

    if not removed and not added:
        print 'No chages to PCI passthrough'
        return [], vm.config

    new_config = copy.deepcopy(vm.config)
    to_delete = set()
    to_set = []

    if removed or added:
        print_title('\nPassthrough devices changes:')

    if removed:
        with PrintEscControl(BOLD):
            print 'These devices are going to be no longer passed through:'
        for number, dev in removed.items():
            del new_config['hostpci'][number]
            to_delete.add(number)
            with PrintEscControl(YELLOW_COLOR):
                print dev
        print

    free_nums = sorted(set([str(x) for x in range(MAX_PASSTHROUGH)]) - number_keep)

    if added:
        if not new_config.get('hostpci'):
            new_config['hostpci'] = QemuConfig.QemuSubvalueWrapper()
        with PrintEscControl(BOLD):
            print 'These devices are going to be added for passing through:'
        for number, dev in zip(free_nums, added):
            if number in to_delete:
                to_delete.remove(number)
            xvga = ',x-vga=on' if dev.class_id == PciDevice.VGA_CONTROLLER else ''
            to_set.extend(['-hostpci%s' % number, '%s,pcie=1%s' % (dev.slot, xvga)])
            new_config['hostpci'][number] = QemuConfig.QemuConfigEntry(to_set[-1])
            with PrintEscControl(GREEN_COLOR):
                print dev
        print

    if to_delete:
        to_set.extend(['-delete', ','.join('hostpci%s' % num for num in to_delete)])

    if passthru and 'q35' not in vm.config.get('machine', [''])[0]:
        to_set.extend(['-machine', 'q35'])
        new_config['machine'] = ['q35']

    return to_set, new_config

def edit_vm_config(vm, config_name, edit_callback, apply_callback):
    while True:
        how_to, new_config = edit_callback(vm)
        if not how_to:
            return
        if not prompt_yesno('Is this what you wanted'):
            continue

        issues = new_config.validate()
        if not issues:
            break
        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '\nCannot apply configuration changes, issues detected:'
        for issue in issues:
            print '*', issue.problem
        print
        if not prompt_yesno('Try editing machine "%s" %s settings again' % (vm.name, config_name)):
            return

    if how_to:
        return apply_callback(vm, how_to)

def apply_qm_options(vm, options):
    print 'Applying changes to "%s" machine configuration...' % vm.name
    call_cmd(['qm', 'set', str(vm.vmid)] + list(options))
    vm.parse_config()

def select_devs_for_passthrough(vm):
    return edit_vm_config(vm, 'passthrough', choose_devs_for_passthrough, apply_qm_options)

class QemuArgsManager:
    QemuArgument = collections.namedtuple('QemuArgument', 'type params')
    QemuArgumentParam = collections.namedtuple('QemuArgumentParam', 'name prefix value')
    QEMU_PARAM_RE = re.compile(r'([^a-zA-Z]*)([^=]+)(=(.*))?')

    def __init__(self, parsed):
        self.qargs = parsed
        self.dirty = False

    @classmethod
    def parse_param_str(cls, param_str):
        if not param_str:
            return []

        params = []
        for param in param_str.split(','):
            try:
                match = cls.QEMU_PARAM_RE.match(param).groups()
            except AttributeError:
                raise ValueError('Malformed qemu argument parameter: %s' % param_str)
            params.append(cls.QemuArgumentParam(name=match[1], prefix=match[0], value=match[3]))
        return params

    @classmethod
    def parse_args(cls, vm):
        result, current_type = [], None
        for arg in vm.config.get('args', []):
            if arg.startswith('-'):
                # new argument type detected
                if current_type is not None:
                    result.append(cls.QemuArgument(type=current_type, params=[]))
                current_type = arg[1:]
            else:
                result.append(cls.QemuArgument(type=current_type, params=cls.parse_param_str(arg)))
                current_type = None
        if current_type is not None:
            result.append(cls.QemuArgument(type=current_type, params=[]))
        return cls(result)

    def remove_arg(self, type, start_params):
        if isinstance(start_params, str):
            start_params = self.parse_param_str(start_params)
        to_remove = []
        for idx, qarg in enumerate(self.qargs):
            if qarg.type == type:
                for qparam, sparam in zip(qarg.params, start_params):
                    if qparam != sparam:
                        break
                else:
                    to_remove.append(idx)
        if to_remove:
            print 'Removing all -%s %s entries from qemu args' % (type, ':'.join(p.name for p in start_params))
            for idx in reversed(to_remove):
                del self.qargs[idx]
            self.dirty = True
        
    def ensure_arg(self, type, start_params, needed_params):
        if isinstance(start_params, str):
            start_params = self.parse_param_str(start_params)
        if isinstance(needed_params, str):
            needed_params = self.parse_param_str(needed_params)

        for qarg in self.qargs:
            if qarg.type == type:
                arg_found = False
                for qparam, sparam in zip(qarg.params, start_params):
                    if qparam != sparam:
                        break
                else:
                    arg_found = True
                if not arg_found:
                    continue

                added_params = []
                for nparam in needed_params:
                    for idx, qparam in enumerate(qarg.params):
                        if qparam.name == nparam.name:
                            if qparam != nparam:
                                added_params.append(nparam)
                                qarg.params[idx] = nparam
                            break
                    else:
                        added_params.append(nparam)
                        qarg.params.append(nparam)

                if added_params:
                    self.dirty = True
                    print 'Added parameters to -%s %s entry of qemu args' % (type, ':'.join(p.name for p in start_params))
                else:
                    print 'Ensured -%s %s entry of qemu args is correct' % (type, ':'.join(p.name for p in start_params))
                return

        self.dirty = True
        print 'Adding missing argument -%s %s to qemu args' % (type, ':'.join(p.name for p in start_params))
        self.qargs.append(self.QemuArgument(type=type, params=list(start_params) + list(needed_params)))

    def append_set_option(self, options):
        if not self.dirty:
            return

        args = []
        for arg in self.qargs:
            if arg.type:
                args.append('-%s' % arg.type)
            params = []
            for param in arg.params:
                if param.value:
                    params.append('%s%s=%s' % (param.prefix, param.name, param.value))
                else:
                    params.append('%s%s' % (param.prefix, param.name))
            if params:
                args.append(','.join(params))
        options.append(('Fine-tuning qemu args', ['-args', subprocess.list2cmdline(args)]))

def enable_macos_support(vm):
    ensure_values = [
        ('bios', 'ovmf', 'VM should use "OVMF" BIOS, please change the settings using Proxmox Options tab and remember to add EFI disk in Hardware tab'),
        ('vga', 'std', 'VM should have "Standard VGA" display, please change the settings using Proxmox Hardware tab'),
        ('ostype', 'other', 'Guest OS type should be set up to "Other", please change the settings using Proxmox Options tab'),
        ('balloon', '0', 'VM should not use memory ballooning, please change the settings using Proxmox Hardware tab'),
    ]
    machine_target = 'pc-q35-2.11'
    cpu_target = 'Penryn'
    net_target = 'e1000-82545em'

    found_problems = [] 
    for name, value, message in ensure_values:
        if vm.config.get(name, [None])[0] != value:
            found_problems.append(message)
    if found_problems:
        issue_word = 'issues' if len(found_problems) > 1 else 'issue'
        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '\nCannot enable MacOS support, %s detected:' % issue_word
        for problem in found_problems:
            print '*', problem

        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '\nAfter fixing the %s please refresh VM list' % issue_word
        return

    actions = []
    if vm.config.get('machine', [None])[0] != machine_target:
        actions.append(('Changing machine to "%s"' % machine_target, ['-machine', machine_target]))
    else:
        print 'Correct machine type already specified'

    if vm.config.get('cpu', [None])[0] != cpu_target:
        actions.append(('Changing CPU to "%s"' % cpu_target, ['-cpu', cpu_target]))
    else:
        print 'Correct CPU already specified'

    if vm.config.get('net'):
        for number, value in vm.config['net'].items():
            if value[0].split('=', 1)[0] == net_target:
                print 'Correct network adapter already specified'
                break
            if value[0].split('=', 1)[0] == 'e1000':
                pieces = value[0].split('=', 1)
                if len(pieces) == 2:
                    new_value = ['%s=%s' % (net_target, pieces[1])]
                else:
                    new_value = [net_target]
                new_value += value[1:]
                actions.append(('Changing network adapter to "%s"' % net_target,
                                ['-net%s' % number, ','.join(new_value)]))
                break
        else:
            with PrintEscControl(YELLOW_COLOR):
                print 'Supported network adapter not found. Please fix the issue using Proxmox Hardware tab by either:'
                print ' * removing all network adapters'
                print ' * adding a Intel E1000 network adapter'
                print ' * changing existing adapter to Intel E1000'
                print 'And then please refresh VM list'
                return

    qemu_args = QemuArgsManager.parse_args(vm)
    oskey = None

    for qarg in qemu_args.qargs:
        if qarg.type == 'device':
            for param in qarg.params:
                if param.name == 'isa-applesmc':
                    break
            else:
                # not an AppleSMC device
                continue
            for param in qarg.params:
                if param.name == 'osk':
                    oskey = param.value
                    break
            break

    print
    print_title('Manage MacOS OSK')
    if oskey:
        print 'Current OS key: %s' % oskey
        if not prompt_yesno('Is current OS key correct'):
            oskey = None
    if not oskey:
        print 'For getting MacOS OSK refer to this guide, section "Fetch the OSK authentication key":'
        print 'https://www.nicksherlock.com/2017/10/installing-macos-high-sierra-on-proxmox-5/'
        oskey = raw_input('\nMacOS OSK: ')

    qemu_args.ensure_arg(type='device', start_params='isa-applesmc', needed_params='osk=%s' % oskey)
    qemu_args.ensure_arg(type='smbios', start_params='', needed_params='type=2')
    qemu_args.ensure_arg(type='cpu', start_params=cpu_target, needed_params='kvm=on,vendor=GenuineIntel,+invtsc,vmware-cpuid-freq=on')

    qemu_args.append_set_option(actions)

    if actions:
        changes = []
        for message, command in actions:
            print message
            changes.extend(command)
        apply_qm_options(vm, changes)
    print 'MacOS enabling complete'

def compute_pci_bridge_passthrough_hack(vm):
    qemu_args = QemuArgsManager.parse_args(vm)
    device_arg_start = QemuArgsManager.parse_param_str('vfio-pci,host,id=hostpci,bus=pcie.0')
    hacked_devs = []
    for qarg in qemu_args.qargs:
        if qarg.type == 'device':
            for qparam, eparam in zip(list(qarg.params) + [None] * 10, device_arg_start):
                if qparam.name != eparam.name or \
                        (eparam.value and (not qparam.value or not qparam.value.startswith(eparam.value))):
                    break
            else:
                hacked_devs.append(qarg)
    
    if hacked_devs:
        message = 'Convert from hacked to normal passthrough'
    elif vm.config.get('hostpci'):
        message = 'Convert from normal passthrough to hacked'
    else:
        print 'No devices were passed through, nothing to do'
        return [], vm.config
        
    if not prompt_yesno(message):
        return [], vm.config

    actions = []
    to_set = []
    new_config = copy.deepcopy(vm.config)

    if hacked_devs:
        parsed = {}
        for qarg in hacked_devs:
            qemu_args.remove_arg(qarg.type, qarg.params)
            
            host_slot, hostpci_num = None, None
            for param in qarg.params:
                if param.name == 'host':
                    host_slot = param.value
                elif param.name == 'id':
                    hostpci_num = param.value.split('.')[0].replace('hostpci', '')
            assert host_slot and hostpci_num
            parsed.setdefault(hostpci_num, []).append(host_slot)
            
        if not new_config.get('hostpci'):
            new_config['hostpci'] = QemuConfig.QemuSubvalueWrapper()
        for hostpci_num, host_slot in parsed.items():
            if len(host_slot) > 1:
                host_slot = host_slot[0].split('.')[0]
            else:
                host_slot = host_slot[0]
            to_set.extend(['-hostpci%s' % hostpci_num, '%s,pcie=1,x-vga=on' % host_slot])
            new_config['hostpci'][hostpci_num] = QemuConfig.QemuConfigEntry(to_set[-1]) 
        
        if to_set:
            actions.append(('Set hostpci entries', to_set))
    else:
        grouped = {}
        for hostpci_num, passthru_cfg in vm.config['hostpci'].items():
            for dev in vm.config.translate_hostpci_to_devices(passthru_cfg):
                grouped.setdefault(dev.slot.split('.')[0], []).append((hostpci_num, dev))
        for slot_start, dev_list in list(grouped.items()):
            for _, dev in dev_list:
                if dev.class_id == PciDevice.VGA_CONTROLLER:
                    break
            else:
                del grouped[slot_start]
        to_delete = set()
        guest_pci_addr = 0x10
        for dev_list in grouped.values():
            dev_list = sorted(dev_list, key=lambda entry: int(entry[1].slot.split('.')[1]))
            first_hostpci_num = dev_list[0][0]
            for idx, (hostpci_num, dev) in enumerate(dev_list):
                if hostpci_num not in to_delete:
                    to_delete.add(hostpci_num)
                    del new_config['hostpci'][hostpci_num]
                qemu_args.ensure_arg(type='device',
                                     start_params='vfio-pci,host=%s' % dev.slot,
                                     needed_params='id=hostpci%(hostpci_num)s.%(pci_idx)s,bus=pcie.0,addr=0x%(guest_pci_addr)x.%(pci_idx)s%(multi)s' % 
                                            {'hostpci_num': first_hostpci_num,
                                             'pci_idx': idx,
                                             'guest_pci_addr': guest_pci_addr,
                                             'multi': ',multifunction=on' if idx == 0 else ''})
            guest_pci_addr += 1

        if to_delete:
            to_set.extend(['-delete', ','.join('hostpci%s' % num for num in to_delete)])
            actions.append(('Remove VGA-related hostpci entries', to_set))
        cpu_type = vm.config.get('cpu', ['kvm64'])[0]
        qemu_args.ensure_arg(type='cpu', start_params=cpu_type,
                             needed_params='hv_time,kvm=off,hv_vendor_id=DendyGeeks,-hypervisor')
        if vm.config.get('vga', [None])[0] != 'none':
            actions.append(('Set emulated VGA to none', ['-vga', 'none']))
            new_config['vga'] = ['none']

    qemu_args.append_set_option(actions)
    if actions:
        changes = []
        for message, command in actions:
            print message
            changes.extend(command)
        return changes, new_config

    return [], vm.config

def toggle_pci_bridge_passthrough_hack(vm):
    return edit_vm_config(vm, 'pci bridge passthrough hacks', compute_pci_bridge_passthrough_hack, apply_qm_options)
    
def stage2():
    print_title('\nDevices available for passing through:')
    passthru = print_devices(lambda dev: dev.is_driven_by_vfio())
    if passthru:
        check_iommu_groups(passthru)
    else:
        with PrintEscControl(BOLD):
            print 'No devices selected'

    if not prompt_yesno('Is this list what you want'):
        with PrintEscControl(BOLD):
            print 'Run "%s --reconf" to reconfigure passthrough devices' % os.path.basename(sys.argv[0])
            sys.exit(0)
    
    print
    vms = list_and_validate_vms()

    while True:
        print

        if vms:
            print_title('Virtual Machines present:')

            for index, vm in enumerate(vms):
                print '%2d. %s' % (index+1, vm.name)

            print

        try:
            val = prompt_int('Enter the VM index to edit (0 - refresh, Ctrl-C - quit): ', 0, len(vms))
        except KeyboardInterrupt:
            with PrintEscControl(GREEN_COLOR):
                print '\nGoodbye! Have fun using Geexmox-tuned Proxmox node!\n'
            break

        if val == 0:
            vms = list_and_validate_vms()
            continue

        vm = vms[val - 1]
        vm.parse_config()

        while True:
            with PrintEscControl(BOLD):
                print '\nEditing "%s" machine.\nSelect an operation to perform:' % vm.name
            print
            ops = [
                ('Show passed through PCI devices', show_passthrough_devs),
                ("Select PCI devices for passing through", select_devs_for_passthrough),
                ("Enable macOS support for the VM", enable_macos_support),
                ('Toggle PCI bridge passthrough hack (useful for Windows 7)', toggle_pci_bridge_passthrough_hack),
            ]
            for index, (op, _) in enumerate(ops):
                print "%2d. %s" % (index+1, op)

            print
            opt = prompt_int('Select an option (0 - select another VM): ', 0, len(ops))
            if opt == 0:
                break
            ops[opt - 1][1](vm)

def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        sys.exit('''Usage: %s [--debug] [--reconf]

Configures given node as a GeexMox one.
Starts installation if node is not running a ProxMox kernel.

    --reconf: forces installation start
    --debug:  shows error stacktraces
    --wget:   use wget for downloading stuff (works around some issues with proxies)
    --help:   shows this text''' % sys.argv[0])

    global download
    if '--wget' in sys.argv:
        download = download_wget
    else:
        download = download_internal

    try:
        if os.geteuid() != ROOT_EUID:
            sys.exit('%s must be run as root' % sys.argv[0])
        if subprocess.check_output(['arch']).strip() != 'x86_64':
            sys.exit('%s can only work on x86_64 OS' % sys.argv[0])

        print ElephantArt.get_mascot()

        is_proxmox_kernel = subprocess.check_output(['uname', '-r']).strip().endswith('-pve')
        if not is_proxmox_kernel or '--reconf' in sys.argv:
            if is_proxmox_kernel:
                print 'ProxMox kernel already running, but user requested reinstallation'
            stage1()
        else:
            stage2()
    except KeyboardInterrupt:
        with PrintEscControl(YELLOW_COLOR + BOLD):
            print '\n\nCancelled by user'
    except Exception as e:
        with PrintEscControl(LIGHT_RED_COLOR):
            with PrintEscControl(BOLD):
                sys.stderr.write('\nFatal error occurred:\n')
            sys.stderr.write('%s\n' % e)
            if '--debug' in sys.argv:
                traceback.print_exc()

if __name__ == '__main__':
    main()
