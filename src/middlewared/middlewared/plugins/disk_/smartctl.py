import asyncio
import functools
import subprocess

from middlewared.common.camcontrol import camcontrol_list
from middlewared.common.smart.smartctl import get_smartctl_args, smartctl
from middlewared.service import accepts, Bool, Dict, CallError, List, private, Service, Str
from middlewared.utils.asyncio_ import asyncio_map


class DiskService(Service):
    smartctl_args_for_disk = {}
    smartctl_args_for_device_lock = asyncio.Lock()

    @private
    async def update_smartctl_args_for_disks(self):
        await self.smartctl_args_for_device_lock.acquire()

        async def update():
            try:
                disks = [
                    disk['devname']
                    for disk in await self.middleware.call(
                        'disk.query',
                        [
                            ['devname', '!=', None],
                            ['togglesmart', '=', True],
                        ],
                    )
                ]

                devices = await camcontrol_list()

                self.smartctl_args_for_disk = dict(zip(
                    disks,
                    await asyncio_map(functools.partial(get_smartctl_args, self.middleware, devices), disks, 8)
                ))
            except Exception:
                self.logger.error("update_smartctl_args_for_disks failed", exc_info=True)
            finally:
                self.smartctl_args_for_device_lock.release()

        asyncio.ensure_future(update())

    @private
    async def smartctl_args(self, disk):
        async with self.smartctl_args_for_device_lock:
            return self.smartctl_args_for_disk.get(disk)

    @accepts(
        Str('disk'),
        List('args', items=[Str('arg')]),
        Dict(
            'options',
            Bool('silent', default=False),
        ),
    )
    @private
    async def smartctl(self, disk, args, options):
        try:
            smartctl_args = await self.middleware.call('disk.smartctl_args', disk)
            if smartctl_args is None:
                raise CallError(f'S.M.A.R.T. is unavailable for disk {disk}')

            cp = await smartctl(smartctl_args + args, check=False, stderr=subprocess.STDOUT,
                                encoding='utf8', errors='ignore')
            if (cp.returncode & 0b11) != 0:
                raise CallError(f'smartctl failed for disk {disk}:\n{cp.stdout}')
        except CallError:
            if options['silent']:
                return None

            raise

        return cp.stdout


async def setup(middleware):
    await middleware.call('disk.update_smartctl_args_for_disks')
