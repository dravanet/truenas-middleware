import bidict
import pathlib


AUTHMETHOD_LEGACY_MAP = bidict.bidict({
    'None': 'NONE',
    'CHAP': 'CHAP',
    'CHAP Mutual': 'CHAP_MUTUAL',
})

# Currently SCST has this limit (scst_vdisk_dev->name)
MAX_EXTENT_NAME_LEN = 64

# Support for basic operations through sysfs
# Implemented operations will support truenas-csi operation.
# These are:
# - extent creation
# - extent deletion
# - target creation
# - target deletion
# - target-extent association creation with lun 0
# - target-extent association deletion with lun 0
# upon update of any of these objects, full original codepath will be invoked
# otherwise, configuration will be applied through sysfs, in O(1) time.


SCST_ROOT = pathlib.Path('/sys/kernel/scst_tgt')


def _scst_ename(e):
    return e['name'].replace('.', '_').replace('/', '-')  # CORE ctl device names are incompatible with SCALE SCST


def _scst_device_set_attribute(dev, attribute, value):
    dev.joinpath(attribute).write_text(value)


class SCSTSysfsHandler:
    def __init__(self, mw, root=SCST_ROOT):
        self.middleware = mw
        self.root = root

    async def handler(self, name):
        return self.root.joinpath('handlers', name)

    async def device(self, name):
        return self.root.joinpath('devices', name)

    async def targetname(self, target):
        global_config = await self.middleware.call('iscsi.global.config')
        return f"{global_config['basename']}:{target['name']}"

    async def targetroot(self, target):
        return self.root.joinpath('targets', 'iscsi', await self.targetname(target))

    async def create_extent(self, extent):
        """ creates an extent """
        if not extent['enabled']:
            return

        name = _scst_ename(extent)
        # Only handle ZVOL and File
        if extent['type'] == 'DISK':
            if not extent['path'].startswith('zvol/'):
                raise RuntimeError("Unsupported disk for live-reconfiguration")

            path = '/dev/' + extent['path']
            handler = "vdisk_blockio"
        elif extent['type'] == 'File':
            path = extent['path']
            handler = "vdisk_fileio"

        parameters = [
            f"blocksize={extent['blocksize']}",
            f"filename={path}",
            f"read_only={1 if extent['ro'] else 0}",
            f"rotational={0 if extent['rpm'] == 'SSD' else 1}",
        ]

        handlerpath = await self.handler(handler)
        handlerpath.joinpath('mgmt').write_text(f"add_device {name} {';'.join(parameters)}")

        device = await self.device(name)

        serial: str = extent['serial']
        if not extent['xen']:
            serial = serial.ljust(31 - len(serial))

        _scst_device_set_attribute(device, 'lb_per_pb_exp', '0' if extent['pblocksize'] else '1')
        _scst_device_set_attribute(device, 'usn', serial)
        _scst_device_set_attribute(device, 'naa_id', extent['naa'])
        _scst_device_set_attribute(device, 't10_vend_id', extent['vendor'])
        _scst_device_set_attribute(device, 't10_dev_id', serial)
        if handler == "vdisk_blockio":
            _scst_device_set_attribute(device, 'threads_num', '32')

    async def delete_extent(self, extent):
        """ creates an extent """
        if not extent['enabled']:
            return

        name = _scst_ename(extent)

        device = await self.device(name)
        if device.is_dir():
            mgmt = device.joinpath('handler', 'mgmt')
            mgmt.write_text(f"del_device {name}")

    # copied from scst.conf.mako, queries tuned

    async def create_target(self, target):
        alias = target.get('alias')
        mutual_chap = None
        chap_users = set()
        initiator_portal_access = set()
        has_per_host_access = False
        for host in await self.middleware.call(
            "datastore.query",
            "services.iscsihosttarget",
                [('target_id', '=', target['id'])]):
            for iqn in await self.middleware.call(
                "datastore.query",
                "services.iscsihostiqn",
                [('host_id', '=', host['id'])],
                    {"relationships": False}):
                initiator_portal_access.add(f'{iqn["iqn"]}\#{host["host"]["ip"]}')
                has_per_host_access = True
        for group in target['groups']:
            if group['authmethod'] != 'NONE':
                auth_list = await self.middleware.call('iscsi.auth.query', [('tag', '=', group['auth'])])

                if group['authmethod'] == 'CHAP_MUTUAL' and not mutual_chap:
                    mutual_chap = f'{auth_list[0]["peeruser"]} {auth_list[0]["peersecret"]}'

                chap_users.update(f'{auth["user"]} {auth["secret"]}' for auth in auth_list)

            portal = (await self.middleware.call('iscsi.portal.query', [('id', '=', group['portal'])]))[0]
            for addr in portal['listen']:
                if addr['ip'] in ('0.0.0.0', '::'):
                    # SCST uses wildcard patterns
                    # https://github.com/truenas/scst/blob/e945943861687d16ae0415207306f75a55bcfd2b/iscsi-scst/usr/target.c#L139-L138
                    address = '*'
                else:
                    address = addr['ip']

                if group['initiator']:
                    group_initiators = (await self.middleware.call('iscsi.initiator.query', [('id', '=', group['initiator'])]))[0]['initiators']
                else:
                    group_initiators = []
                if not has_per_host_access:
                    group_initiators = group_initiators or ['*']
                for initiator in group_initiators:
                    initiator_portal_access.add(f'{initiator}#{address}')

        targetname = await self.targetname(target)
        iscsimgmt = self.root.joinpath('targets', 'iscsi', 'mgmt')
        iscsimgmt.write_text(f"add_target {targetname}")
        targetroot = self.root.joinpath('targets', 'iscsi', targetname)

        targetroot.joinpath('rel_tgt_id').write_text(str(target['rel_tgt_id']))
        targetroot.joinpath('enabled').write_text("1")
        targetroot.joinpath('per_portal_acl').write_text("1")
        if alias:
            targetroot.joinpath('alias').write_text(alias)
        for chap_auth in chap_users:
            iscsimgmt.write_text(f"add_target_attribute {targetname} IncomingUser {chap_auth}")
        if mutual_chap:
            iscsimgmt.write_text(f"add_target_attribute {targetname} OutgoingUser {mutual_chap}")

        targetroot.joinpath('ini_groups').joinpath('mgmt').write_text(f"create security_group")
        grouproot = targetroot.joinpath('ini_groups', 'security_group')
        inimgmt = grouproot.joinpath('initiators', 'mgmt')
        for access_control in initiator_portal_access:
            inimgmt.write_text(f"add {access_control}")

    async def delete_target(self, target):
        targetname = await self.targetname(target)
        iscsimgmt = self.root.joinpath('targets', 'iscsi', 'mgmt')
        iscsimgmt.write_text(f"del_target {targetname}")

    async def _get_iscsi_target(self, id_):
        return (await self.middleware.call(
            'datastore.query',
            'services.iscsitarget',
            [('id', '=', id_)],
            {'prefix': 'iscsi_target_'},
        ))[0]

    async def _get_iscsi_extent(self, id_):
        return (await self.middleware.call(
            'datastore.query',
            'services.iscsitargetextent',
            [('id', '=', id_)],
            {'prefix': 'iscsi_target_extent_'},
        ))[0]

    async def create_target_to_extent(self, t2e):
        if not isinstance(t2e['lunid'], int):
            raise AttributeError(name='lunid')

        target = await self._get_iscsi_target(t2e['target'])
        extent = await self._get_iscsi_extent(t2e['extent'])

        ename = _scst_ename(extent)
        targetroot = await self.targetroot(target)
        targetroot.joinpath('ini_groups', 'security_group', 'luns', 'mgmt') \
            .write_text(f"add {ename} {t2e['lunid']}")

    async def delete_target_to_extent(self, t2e):
        if not isinstance(t2e['lunid'], int):
            raise AttributeError(name='lunid')

        target = await self._get_iscsi_target(t2e['target'])

        targetroot = await self.targetroot(target)
        targetroot.joinpath('ini_groups', 'security_group', 'luns', 'mgmt') \
            .write_text(f"del {t2e['lunid']}")
