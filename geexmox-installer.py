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

ROOT_EUID = 0

# Console ESC flags
BOLD = '\x1b[1m'
DIMMED = '\x1b[2m'
# Reset console ESC flags
RESET_BOLD = '\x1b[21m'
RESET_DIMMED = '\x1b[22m'

# Console ESC colors
RED_COLOR = '\x1b[31m'
LIGHT_RED_COLOR = '\x1b[91m'
YELLOW_COLOR = '\x1b[93m'
GREEN_COLOR = '\x1b[92m'
DEFAULT_COLOR = '\x1b[39m'

RESET_TABLE = {
    RED_COLOR: DEFAULT_COLOR,
    LIGHT_RED_COLOR: DEFAULT_COLOR,
    YELLOW_COLOR: DEFAULT_COLOR,
    GREEN_COLOR: DEFAULT_COLOR,
    BOLD: RESET_BOLD,
    DIMMED: RESET_DIMMED,
}

APT_CONFIGS = [
    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/preferences.d/geexmox',
     '/etc/apt/preferences.d/geexmox'),
    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/sources.list.d/geexmox.list',
     '/etc/apt/sources.list.d/geexmox.list')
]

MAX_PASSTHROUGH = 4

class PrintEscControl:
    @staticmethod
    def __switch_color(color):
        for handle in (sys.stdout, sys.stderr):
            handle.write(color)
            handle.flush()

    def __init__(self, begin_seq, end_seq=None):
        self.begin_seq = begin_seq
        if end_seq is not None:
            self.end_seq = end_seq
        else:
            end_seq = []
            for color in reversed(begin_seq.split('\x1b')):
                if not color:
                    continue
                end_seq.append(RESET_TABLE['\x1b' + color])
            self.end_seq = ''.join(end_seq)

    def __enter__(self, *a, **kw):
        self.__switch_color(self.begin_seq)
    def __exit__(self, *a, **kw):
        self.__switch_color(self.end_seq)

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
        if self['bios'][0] == 'ovmf':
            if not self.get('efidisk', {}).get('0', None):
                issues.append(self.ValidateResult(
                        problem='Missing EFI disk with OVMF bios selected',
                        solution='Please add EFI disk using ProxMox Hardware menu',
                        have_to_stop=True))

        # check that if we're passing something thru we use OVMF and don't use ballooning
        if self.get('hostpci'):
            if self['bios'][0] != 'ovmf':
                issues.append(self.ValidateResult(
                        problem='Passing throught devices on non-OVMF bios is unsupported',
                        solution='Switch BIOS to OVMF using ProxMox Options menu',
                        have_to_stop=True))
            if self.get('balloon') and self['balloon'][0] != '0':
                issues.append(self.ValidateResult(
                        problem='Cannot enable memory ballooning when passing through PCI devices',
                        solution='Disable memory ballooning using ProxMox Hardware menu',
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
                        problem='Cannot pass through device at %s: not driven by a kernel module' % item,
                        solution='Run "%s --reconf", select correct devices and reboot' % os.path.basename(sys.argv[1]),
                        have_to_stop=True))
            if not dev.is_driven_by_vfio():
                issues.append(self.ValidateResult(
                        problem='Bad driver for device at %s, should be %s for passing through' % (item, PciDevice.VFIO_DRIVER),
                        solution='Run "%s --reconf", select correct devices and reboot' % os.path.basename(sys.argv[1]),
                        have_to_stop=True))

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
        print 'Getting config for "%s"...' % self.name
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
                    print BOLD + label + RESET_BOLD
                    title_shown = True
                print "%2d. %s" % (len(printed_devs), dev)
            elif show_disabled:
                if not title_shown:
                    print BOLD + label + RESET_BOLD
                    title_shown = True
                print '%s    %s%s' % (RED_COLOR, dev, DEFAULT_COLOR)
    
        if title_shown:
            print

    perform_grouping("VGA CONTROLLERS (videocards)",
            lambda dev: dev.class_id == PciDevice.VGA_CONTROLLER)
    perform_grouping("USB CONTROLLERS",
            lambda dev: dev.class_id == PciDevice.USB_CONTROLLER)
    perform_grouping("OTHER DEVICES",
            lambda dev: dev.class_id not in (PciDevice.USB_CONTROLLER, PciDevice.VGA_CONTROLLER))
    
    return printed_devs

def download(url, target):
    print 'Downloading %s as %s' % (url, target)
    try:
        with contextlib.closing(urllib.urlopen(url)) as page:
            with open(target, 'wb') as f:
                f.write(page.read())
    except IOError:
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
    for url, target in APT_CONFIGS:
        download(url, target)

def disable_pve_enterprise(verbose=True):
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


def install_proxmox():
    # installing ProxMox by following official guide:
    # https://pve.proxmox.com/wiki/Install_Proxmox_VE_on_Debian_Stretch
    hostname = subprocess.check_output(['hostname']).strip()
    hostname_ip = subprocess.check_output(['hostname', '--ip-address']).strip()
    with open('/etc/hosts') as hosts:
        for line in hosts:
            line = line.split('#')[0].strip()
            if not line:
                continue
            if line.split()[0] == hostname_ip:
                print 'Current host %(b)s%(h)s%(r)s ip address %(b)s%(ip)s%(r)s is present in /etc/hosts' % \
                        {'b': BOLD, 'r': RESET_BOLD, 'h': hostname, 'ip': hostname_ip}
                break
        else:
            print 'Current host %(b)s%(h)s%(r)s ip address %(b)s%(ip)s%(r)s not present in /etc/hosts' % \
                    {'b': BOLD, 'r': RESET_BOLD, 'h': hostname, 'ip': hostname_ip}
            print 'It should be there for ProxMox installation to succeed.'
            if prompt_yesno('Add %s entry to /etc/hosts' % hostname):
                with open('/etc/hosts', 'a+') as hosts:
                    hosts.write('\n%(ip)s\t%(host)s\t\t# automagically added by %(prog)s\n' %
                            {'ip': hostname_ip, 'host': hostname, 'prog': os.path.basename(sys.argv[0])})

    print 'Adding ProxMox repo and key...'
    with open('/etc/apt/sources.list.d/pve-install-repo.list', 'w') as pve:
        pve.write('deb [arch=amd64] http://download.proxmox.com/debian/pve stretch pve-no-subscription\n')
    download('http://download.proxmox.com/debian/proxmox-ve-release-5.x.gpg',
            '/etc/apt/trusted.gpg.d/proxmox-ve-release-5.x.gpg')
    
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
    if no_enterprise:
        disable_pve_enterprise(verbose=False)

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
    
    inject_geexmox_overrides() 
    install_proxmox()

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
            print '\nPlease fix issues above and re-run %s to continue configuring' % os.path.basename(sys.argv[0])
            #XXX sys.exit(1)

    return vms

def choose_devs_for_passthrough(vm):
    if vm.config.get('hostpci'):
        print_title('\nPCI devices already passed through:')
        for dev in vm.config.get_hostpci_devices():
            print dev
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

    return to_set, new_config

def edit_vm_config(vm, edit_callback, apply_callback):
    while True:
        how_to, new_config = edit_callback(vm)
        if not how_to:
            return
        if not prompt_yesno('Is this what you wanted'):
            continue

        issues = new_config.validate()
        if not issues:
            break
        with PrintEscControl(YELLOW_COLOR):
            print 'Cannot apply configuration changes, issues detected'
        for issue in issues:
            print issue.problem

    if how_to:
        return apply_callback(vm, how_to)

def apply_qm_options(vm, options):
    print 'Applying changes to "%s" machine configuration...' % vm.name
    call_cmd(['qm', 'set', str(vm.vmid)] + list(options))
    vm.parse_config()

def select_devs_for_passthrough(vm):
    return edit_vm_config(vm, choose_devs_for_passthrough, apply_qm_options)

def enable_macos_support(vm):
    ensure_values = [
        ('bios', 'ovmf', 'MacOS should run using OVMF BIOS, please change the settings using Proxmox Options tab'),
        ('vga', 'std', 'MacOS should run using Standard VGA display, please change the settings using Proxmox Hardware tab'),
    ]
    machine_target = 'pc-q35-2.11'
    cpu_target = 'Penryn'
    net_target = 'e1000-82545em'

    found_problems = 0
    for name, value, message in ensure_values:
        if vm.config[name][0] != value:
            with PrintEscControl(YELLOW_COLOR):
                print message
            found_problems += 1
    if found_problems > 0:
        with PrintEscControl(YELLOW_COLOR):
            print 'After fixing the %s please re-run %s' % ('issues' if found_problems > 1 else 'issue', os.path.basename(sys.argv[0]))
        return

    options = []
    if vm.config['machine'][0] != machine_target:
        options.append(('Changing machine to "%s"' % machine_target, ['-machine', machine_target]))
    else:
        print 'Correct machine type already specified'

    if vm.config['cpu'][0] != cpu_target:
        options.append(('Changing CPU to "%s"' % cpu_target, ['-cpu', cpu_target]))
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
                options.append(('Changing network adapter to "%s"' % net_target,
                                ['-net%s' % number, ','.join(new_value)]))
                break
        else:
            with PrintEscControl(YELLOW_COLOR):
                print 'Either drop network connectivity or add a E1000 network adapter and re-run %s' % os.path.basename(sys.argv[0])
                return

    oskey, apple_smc_index = None, -1
    for idx, arg in enumerate(vm.config.get('args', [])):
        subargs = arg.split(',')
        if subargs[0] != 'isa-applesmc':
            continue
        apple_smc_index = idx
        params = {}
        for subarg in subargs[1:]:
            if '=' in subarg:
                key, value = subarg.split('=', 1)
                params[key] = value
        oskey = params.get('osk')
        break

    print
    print_title('Manage MacOS OSK')
    if oskey:
        print 'Current OS key: "%s"' % oskey
        if not prompt_yesno('Is current OS key correct'):
            oskey = None
    if not oskey:
        print 'For getting MacOS OSK refer to this guide, section "Fetch the OSK authentication key":'
        print 'https://www.nicksherlock.com/2017/10/installing-macos-high-sierra-on-proxmox-5/'
        oskey = raw_input('\nMacOS OSK: ')

    # TODO: implement -args adding to "options"
    # TODO: implement "options" application

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

        print_title('Virtual Machines present:')

        for index, vm in enumerate(vms):
            print '%2d. %s' % (index+1, vm.name)

        print

        val = prompt_int('Enter the VM index to edit (0 - exit): ', 0, len(vms))
        if val == 0:
            break

        vm = vms[val - 1]

        while True:
            with PrintEscControl(BOLD):
                print '\nEditing "%s" machine.\nSelect an operation to perform:' % vm.name
            print
            ops = [
                ("Select PCI devices for passing through", select_devs_for_passthrough),
                ("Enable macOS support for the VM", enable_macos_support)
            ]
            for index, (op, _) in enumerate(ops):
                print "%2d. %s" % (index+1, op)

            print
            opt = prompt_int('Select an option (0 - select another VM): ', 0, len(ops))
            if opt == 0:
                break
            ops[opt - 1][1](vm)

if __name__ == '__main__':
    if '--help' in sys.argv or '-h' in sys.argv:
        sys.exit('''Usage: %s [--debug] [--reconf]

Configures given node as a GeexMox one.
Starts installation if node is not running a ProxMox kernel.

    --reconf: forces installation start
    --debug:  shows error stacktraces
    --help:   shows this text''' % sys.argv[0])

    try:
        if os.geteuid() != ROOT_EUID:
            sys.exit('%s must be run as root' % sys.argv[0])
        if subprocess.check_output(['arch']).strip() != 'x86_64':
            sys.exit('%s can only work on x86_64 OS' % sys.argv[0])

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

