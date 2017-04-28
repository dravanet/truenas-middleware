# -*- coding: utf-8 -*-
# Generated by Django 1.10.3 on 2017-04-20 02:35
from __future__ import unicode_literals

from django.db import migrations
import freenasUI.freeadmin.models.fields

def change_cifs_vfsobjects_defaults(apps, schema_editor):
    cifs_shares = apps.get_model('sharing', 'CIFS_Share').objects.all()
    if not cifs_shares:
        return

    for share in cifs_shares:
        if not share.cifs_vfsobjects:
            continue 

        new_vfs_objects = []
        if 'zfs_space' not in share.cifs_vfsobjects:
            new_vfs_objects.append('zfs_space')
        if 'zfsacl' not in share.cifs_vfsobjects:
            new_vfs_objects.append('zfsacl')

        for obj in share.cifs_vfsobjects:
            new_vfs_objects.append(obj)

        share.cifs_vfsobjects = new_vfs_objects
        share.save()

class Migration(migrations.Migration):

    dependencies = [
        ('sharing', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cifs_share',
            name='cifs_vfsobjects',
            field=freenasUI.freeadmin.models.fields.MultiSelectField(blank=True, choices=[('acl_tdb', 'acl_tdb'), ('acl_xattr', 'acl_xattr'), ('aio_fork', 'aio_fork'), ('aio_pthread', 'aio_pthread'), ('audit', 'audit'), ('cacheprime', 'cacheprime'), ('cap', 'cap'), ('catia', 'catia'), ('commit', 'commit'), ('crossrename', 'crossrename'), ('default_quota', 'default_quota'), ('dfs_samba4', 'dfs_samba4'), ('dirsort', 'dirsort'), ('expand_msdfs', 'expand_msdfs'), ('extd_audit', 'extd_audit'), ('fake_acls', 'fake_acls'), ('fake_perms', 'fake_perms'), ('fruit', 'fruit'), ('full_audit', 'full_audit'), ('linux_xfs_sgid', 'linux_xfs_sgid'), ('media_harmony', 'media_harmony'), ('netatalk', 'netatalk'), ('offline', 'offline'), ('posix_eadb', 'posix_eadb'), ('preopen', 'preopen'), ('readahead', 'readahead'), ('readonly', 'readonly'), ('shadow_copy', 'shadow_copy'), ('shadow_copy_test', 'shadow_copy_test'), ('shell_snap', 'shell_snap'), ('skel_opaque', 'skel_opaque'), ('skel_transparent', 'skel_transparent'), ('snapper', 'snapper'), ('streams_depot', 'streams_depot'), ('streams_xattr', 'streams_xattr'), ('syncops', 'syncops'), ('time_audit', 'time_audit'), ('unityed_media', 'unityed_media'), ('winmsa', 'winmsa'), ('worm', 'worm'), ('xattr_tdb', 'xattr_tdb'), ('zfs_space', 'zfs_space'), ('zfsacl', 'zfsacl')], default='zfs_space,zfsacl,streams_xattr,aio_pthread', max_length=255, verbose_name='VFS Objects'),
        ),
        migrations.RunPython(
            change_cifs_vfsobjects_defaults
        ),
    ]
