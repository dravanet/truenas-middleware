import base64
import os

from Crypto.Cipher import AES
from Crypto.Util import Counter

from middlewared.service import Service


PWENC_BLOCK_SIZE = 32
PWENC_FILE_SECRET = '/data/pwenc_secret'
PWENC_PADDING = b'{'
PWENC_CHECK = 'Donuts!'


class PWEncService(Service):

    class Config:
        private = True

    def file_secret_path(self):
        return PWENC_FILE_SECRET

    def generate_secret(self, reset_passwords=True):
        secret = os.urandom(PWENC_BLOCK_SIZE)
        with open(PWENC_FILE_SECRET, 'wb') as f:
            os.chmod(PWENC_FILE_SECRET, 0o600)
            f.write(secret)

        settings = self.middleware.call_sync('datastore.config', 'system.settings')
        self.middleware.call_sync('datastore.update', 'system.settings', settings['id'], {
            'stg_pwenc_check': self.encrypt(PWENC_CHECK),
        })

        if reset_passwords:
            for table, field in (
                ('directoryservice_activedirectory', 'ad_bindpw'),
                ('directoryservice_ldap', 'ldap_bindpw'),
                ('services_dynamicdns', 'ddns_password'),
                ('services_snmp', 'snmp_v3_password'),
                ('services_snmp', 'snmp_v3_privpassphrase'),
                ('services_ssh', 'ssh_privatekey'),
                ('services_ssh', 'ssh_host_dsa_key'),
                ('services_ssh', 'ssh_host_ecdsa_key'),
                ('services_ssh', 'ssh_host_ed25519_key'),
                ('services_ssh', 'ssh_host_key'),
                ('services_ssh', 'ssh_host_rsa_key'),
                ('services_s3', 's3_secret_key'),
                ('system_certificate', 'cert_privatekey'),
                ('system_certificateauthority', 'cert_privatekey'),
                ('services_webdav', 'webdav_password'),
                ('services_ups', 'ups_monpwd'),
                ('system_email', 'em_pass'),
            ):
                self.middleware.call_sync('datastore.sql', f'UPDATE {table} SET {field} = \'\'')

    def check(self):
        try:
            settings = self.middleware.call_sync('datastore.config', 'system.settings')
        except IndexError:
            self.middleware.call_sync('datastore.insert', 'system.settings', {})
            settings = self.middleware.call_sync('datastore.config', 'system.settings')
        try:
            return self.decrypt(settings['stg_pwenc_check']) == PWENC_CHECK
        except (IOError, ValueError):
            return False

    @staticmethod
    def get_secret():
        with open(PWENC_FILE_SECRET, 'rb') as f:
            return f.read()

    def encrypt(self, data):
        return encrypt(data)

    def decrypt(self, encrypted, _raise=False):
        return decrypt(encrypted, _raise)


async def setup(middleware):
    if not await middleware.call('pwenc.check'):
        await middleware.call('pwenc.generate_secret')


def encrypt(data):
    data = data.encode('utf8')

    def pad(x):
        return x + (PWENC_BLOCK_SIZE - len(x) % PWENC_BLOCK_SIZE) * PWENC_PADDING

    nonce = os.urandom(8)
    cipher = AES.new(PWEncService.get_secret(), AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    encoded = base64.b64encode(nonce + cipher.encrypt(pad(data)))
    return encoded.decode()


def decrypt(encrypted, _raise=False):
    if not encrypted:
        return ''
    try:
        encrypted = base64.b64decode(encrypted)
        nonce = encrypted[:8]
        encrypted = encrypted[8:]
        cipher = AES.new(PWEncService.get_secret(), AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
        return cipher.decrypt(encrypted).rstrip(PWENC_PADDING).decode('utf8')
    except Exception:
        if _raise:
            raise
        return ''
