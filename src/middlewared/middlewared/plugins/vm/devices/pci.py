import subprocess

from middlewared.service import CallError
from middlewared.schema import Dict, Str

from .device import Device
from .utils import ACTIVE_STATES, create_element, LIBVIRT_URI


class PCI(Device):

    schema = Dict(
        'attributes',
        Str('pptdev', required=True, empty=False),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def detach_device(self):
        cp = subprocess.Popen(
            ['virsh', '-c', LIBVIRT_URI, 'nodedev-detach', self.passthru_device()],
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL
        )
        stderr = cp.communicate()[1]
        if cp.returncode:
            raise CallError(f'Unable to detach {self.passthru_device()} PCI device: {stderr.decode()}')

    def reattach_device(self):
        cp = subprocess.Popen(
            ['virsh', '-c', LIBVIRT_URI, 'nodedev-reattach', self.passthru_device()],
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL
        )
        stderr = cp.communicate()[1]
        if cp.returncode:
            raise CallError(f'Unable to re-attach {self.passthru_device()} PCI device: {stderr.decode()}')

    def pre_start_vm_device_setup(self, *args, **kwargs):
        device = self.get_details()
        if not device['error'] and not device['available']:
            self.detach_device()

    def is_available(self):
        return self.get_details()['available']

    def identity(self):
        return str(self.passthru_device())

    def passthru_device(self):
        return str(self.data['attributes']['pptdev'])

    def get_vms_using_device(self):
        devs = self.middleware.call_sync(
            'vm.device.query', [['attributes.pptdev', '=', self.passthru_device()], ['dtype', '=', 'PCI']]
        )
        return self.middleware.call_sync('vm.query', [['id', 'in', [dev['vm'] for dev in devs]]])

    def safe_to_reattach(self):
        return not self.get_details()['error'] and all(
            vm['status']['state'] not in ACTIVE_STATES for vm in self.get_vms_using_device()
        )

    def post_stop_vm(self, *args, **kwargs):
        if self.safe_to_reattach():
            try:
                self.reattach_device()
            except CallError:
                self.middleware.logger.error('Failed to re-attach %s device', self.passthru_device(), exc_info=True)

    def get_details(self):
        return self.middleware.call_sync('vm.device.passthrough_device', self.passthru_device())

    def xml(self, *args, **kwargs):
        address_info = {
            k: hex(int(v)) for k, v in self.get_details()['capability'].items()
            if k in ('domain', 'bus', 'slot', 'function')
        }

        return create_element(
            'hostdev', mode='subsystem', type='pci', managed='yes', attribute_dict={
                'children': [
                    create_element('source', attribute_dict={'children': [create_element('address', **address_info)]}),
                ]
            }
        )

    def _validate(self, device, verrors, old=None, vm_instance=None, update=True):
        pptdev = device['attributes'].get('pptdev')
        device_details = self.middleware.call_sync('vm.device.passthrough_device', pptdev)
        if device_details['error']:
            verrors.add(
                'attribute.pptdev',
                f'Not a valid choice. The PCI device is not available for passthru: {device_details["error"]}'
            )
        elif device_details['critical']:
            verrors.add(
                'attribute.pptdev',
                f'{device_details["controller_type"]!r} based PCI devices are critical for system function '
                'and cannot be used for PCI passthrough'
            )

        if not self.middleware.call_sync('vm.device.iommu_enabled'):
            verrors.add('attribute.pptdev', 'IOMMU support is required.')

        if old and vm_instance and vm_instance['status']['state'] in ACTIVE_STATES and old[
            'attributes'
        ].get('pptdev') != pptdev:
            verrors.add(
                'attribute.pptdev',
                'Changing PCI device is not allowed while the VM is active.'
            )
