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
YELLOW_COLOR = '\x1b[33m'
DEFAULT_COLOR = '\x1b[39m'


APT_CONFIGS = [
    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/preferences.d/geexmox', '/etc/apt/preferences.d/geexmox'),
    ('https://dendygeeks.github.io/geexmox-pve-overrides/etc/apt/sources.list.d/geexmox.list', '/etc/apt/sources.list.d/geexmox.list')
]

class PrintEscControl:
    @staticmethod
    def __switch_color(color):
        for handle in (sys.stdout, sys.stderr):
            handle.write(color)
            handle.flush()

    def __init__(self, begin_seq, end_seq):
        self.begin_seq, self.end_seq = begin_seq, end_seq

    def __enter__(self, *a, **kw):
        self.__switch_color(self.begin_seq)
    def __exit__(self, *a, **kw):
        self.__switch_color(self.end_seq)

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

    def is_same_addr(self, slot):
        addr = self.slot + ('.0' if not self.is_function else '')
        return addr.startswith(slot)

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

QEMU_CONFIG_NAME_TO_VALUE = {
    'args': QemuConfigArgs,
    'description': QemuConfigDescription,
}

class VmNode:
    STOPPED = 'stopped'
    RUNNING = 'running'

    ENDING_DIGITS = re.compile(r'^(.*)(\d+)$')
    PCI_SLOT_ADDR = re.compile(r'^\d+(:\d+(\.\d+)?)?')

    class IncorrectConfigException(Exception):
        def __init__(self, vm_node, message):
            Exception.__init__(self, None, 'Incorrect config for %s node: %s' % (vm_node.vmid, message))

    def __init__(self, vmid, name, status, mem, bootdisk, pid):
        self.vmid, self.name, self.status, self.mem, self.bootdisk, self.pid = \
                vmid, name, status, mem, bootdisk, pid
        self.config = {}
    
    @classmethod
    def parse_qmlist_dict(cls, dct):
        return cls(dct['VMID'], dct['NAME'], dct['STATUS'], dct['MEM(MB)'], dct['BOOTDISK(GB)'], dct['PID']) 

    def __str__(self):
        subst = dict(self.__dict__)
        return '%(vmid)s %(name)s %(status)s %(mem)s %(bootdisk)s %(pid)s' % subst

    def parse_config(self):
        lines = subprocess.check_output(['qm', 'config', self.vmid]).splitlines()
        for line in lines:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = QEMU_CONFIG_NAME_TO_VALUE.get(key, QemuConfigEntry)(value.strip()) 

            if self.ENDING_DIGITS.match(key):
                key, number = self.ENDING_DIGITS.match(key).groups()
                self.config.setdefault(key, {})[number] = value
            else:
                self.config[key] = value

    def validate_config(self):
        # check that OVMF bios has EFI disk
        if self.config['bios'].value[0] == 'ovmf':
            if not self.config.get('efidisk', {}).get('0', None):
                raise self.IncorrectConfigException(self, 'Missing EFI disk with OVMF bios selected')

        # check that if we're passing something thru we use OVMF and don't use ballooning
        if self.config.get('hostpci', {}):
            if self.config['bios'].value[0] != 'ovmf':
                raise self.IncorrectConfigException(self, 'Passing throught devices on non-OVMF bios is unsupported')
            if self.config.get('balloon', None) and self.config['balloon'].value[0] != '0':
                raise self.IncorrectConfigException(self, 'Cannot enable memory ballooning when passing through PCI devices')
            if len(self.config['hostpci']) > 4:
                raise self.IncorrectConfigException(self, 'Cannot have more than 4 PCI devices passed through')

        # check that PCI passed through are driven by vfio
        for number, passthru_cfg in self.config.get('hostpci', {}).items():
            for item in passthru_cfg.value:
                if self.PCI_SLOT_ADDR.match(item):
                    for dev in PciDeviceList.os_collect():
                        if dev.is_same_addr(item):
                            if not dev.can_passthru():
                                raise self.IncorrectConfigException(self,
                                        'Cannot pass through device at %s: not driven by a kernel module' % item)
                            if not dev.is_driven_by_vfio(): 
                                raise self.IncorrectConfigException(self,
                                        'Bad driver for device at %s, should be %s for passing through' % (item, PciDevice.VFIO_DRIVER))

        # check that if '-cpu' is present in 'args' it matches global 'cpu'
        if 'args' in self.config:
            cpu_index = self.config['args'].value.index('-cpu')
            if cpu_index > 0:
                if cpu_index + 1 >= len(self.config['args'].value):
                    raise self.IncorrectConfigException(self, 'No cpu value present for -cpu argument: %s' % self.config['args'])
                if self.config['cpu'].value[0] not in self.config['args'].value[cpu_index + 1]:
                    raise self.IncorrectConfigException(self, 'CPU type in args differs from global CPU type')



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
        print BOLD + label + RESET_BOLD
        for dev in PciDeviceList.os_collect():
            if dev.is_function or not predicate(dev):
                continue
            if dev.can_passthru():
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

def download(url, target):
    print 'Downloading %s as %s' % (url, target)
    try:
        with contextlib.closing(urllib.urlopen(url)) as page:
            with open(target, 'wb') as f:
                f.write(page.read())
    except IOError:
        raise IOError("Can't download the file %s as %s" % (url, target))

def prompt_yesno(msg, default_answer=True):
    prompt = '%s? [%s] ' % (msg, 'Y/n' if default_answer else 'y/N')
    with PrintEscControl(BOLD, RESET_BOLD):
        while True:
            ans = raw_input(prompt).strip().lower()
            if not ans:
                return default_answer
            if ans in ('y', 'yes'):
                return True
            if ans in ('n', 'no'):
                return False

def prompt_comma_list(msg, min_val, max_val):
    with PrintEscControl(BOLD, RESET_BOLD):
        while True:
            ans = raw_input(msg).strip().split(',')
            try:
                result = [int(e.strip()) for e in ans if e.strip()]
                for e in result:
                    if e < min_val or e > max_val:
                        raise ValueError()
            except ValueError:
                with PrintEscControl(RED_COLOR, DEFAULT_COLOR):
                    print 'Incorrect input: enter comma-separated list of indices from %s to %s\n' % (min_val, max_val)
                continue
            return result

def get_module_depends(modname):
    try:
        modinfo = subprocess.check_output(['modinfo', modname], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        if ('%s not found' % modname) in err.output:
            return []
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
            with PrintEscControl(YELLOW_COLOR, DEFAULT_COLOR):
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
    with PrintEscControl(DIMMED, RESET_DIMMED):
        subprocess.check_call(['apt-get', 'update'])
    print
    if prompt_yesno('ProxMox recommends dist-upgrade, perform now'):
        print 'Upgrading distribution...'
        with PrintEscControl(DIMMED, RESET_DIMMED):
            subprocess.check_call(['apt-get', 'dist-upgrade', '-y'])

    print '\nInstalling ProxMox...'
    with PrintEscControl(DIMMED, RESET_DIMMED):
        subprocess.check_call(['apt-get', 'install', '-y', 'proxmox-ve', 'open-iscsi'])
    print
    if prompt_yesno('ProxMox recommends installing postfix, install', default_answer=False):
        with PrintEscControl(DIMMED, RESET_DIMMED):
            subprocess.check_call(['apt-get', 'install', '-y', 'postfix'])
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

    modprobe_cfg.append(('softdep vfio-pci', ' '.join(['post:'] + sorted(device_modules))))
    for module in sorted(device_modules):
        modprobe_cfg.append(('softdep %s' % module, 'pre: vfio-pci'))
    modprobe_cfg.append(('options vfio-pci', 'ids=%s' % ','.join(sorted(device_ids))))

    not_found = []
    for starter, value in modprobe_cfg:
        found_starter = False
        for fname in glob.glob('/etc/modprobe.d/*.conf'):
            content, do_patch = [], False 
            with open(fname) as f:
                for line in f:
                    no_comment = line.split('#')[0].strip()
                    if no_comment.startswith(starter):
                        if no_comment[len(starter):].strip() != value:
                            with PrintEscControl(YELLOW_COLOR, DEFAULT_COLOR):
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
        with PrintEscControl(DIMMED, RESET_DIMMED):
            subprocess.check_call(['update-initramfs', '-u', '-k', 'all'])

def stage1():
    if CpuVendor.os_collect() != CpuVendor.INTEL:
        sys.stderr.write('Non-Intel CPUs are not fully supported by GeexMox. Pull requests are welcome! :)\n')
    
    inject_geexmox_overrides() 
    install_proxmox()

    with PrintEscControl(BOLD, RESET_BOLD):
        msg = 'PCI devices present:'
        print '%s\n%s\n' % (msg, '=' * len(msg))

    devices = print_devices()

    while True:
        passthru = prompt_comma_list('Input comma-separated list of devices to enable passthrough for: ', 1, len(devices))
        if passthru:
            with PrintEscControl(BOLD, RESET_BOLD):
                print '\nDevices selected for passing through:'
            for idx in passthru:
                print devices[idx - 1]
        else:
            with PrintEscControl(BOLD, RESET_BOLD):
                print '\nNo devices selected for passing through'
        print
        if prompt_yesno('Is it correct'):
            break

    if passthru:
        pass_devices = [devices[idx - 1] for idx in passthru]
        for parent_device in list(pass_devices):
            pass_devices.extend(PciDeviceList.get_functions(parent_device))
        ensure_vfio(pass_devices)

def stage2():
    print 'Nobody here'

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
    except Exception as e:
        print LIGHT_RED_COLOR
        print BOLD + "Fatal error occured:" + RESET_BOLD
        print e
        if '--debug' in sys.argv:
            traceback.print_exc()
        print DEFAULT_COLOR
        

