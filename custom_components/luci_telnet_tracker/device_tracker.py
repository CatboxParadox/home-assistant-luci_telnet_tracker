"""
OpenWRT/luci Telnet-based tracker.

Tested on a Zyxel NBG6604 which has luci but lacks the RPC module or a
possibility to install it in order to use https://www.home-assistant.io/integrations/luci/
"""
import logging
import re
from collections import namedtuple
from datetime import timedelta
import telnetlib

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (CONF_HOST, CONF_USERNAME, CONF_PASSWORD)
from homeassistant.util import Throttle

PROMPT = b':~# '
_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = 'exclude'
CONF_INCLUDE = 'include'
CONF_READ_TIMEOUT = 'read_timeout'

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=10)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Optional(CONF_INCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_EXCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_READ_TIMEOUT, default=2.0):
        cv.time_period_seconds
})


def get_scanner(hass, config):
    """Validate the configuration and return a LuciTelnetScanner scanner."""
    return LuciTelnetScanner(config[DOMAIN])

Device = namedtuple('Device', ['mac', 'signal', 'bandwidth', 'interface', 'ip'])

class LuciTelnetScanner(DeviceScanner):
    """This class scans for devices using Telnet"""

    @staticmethod
    def parse_clients(data, iface):
        clients = { }
        for raw_client in re.findall(r'\.push\(([^;]+)\);', data):
            client = { 'interface': iface }
            for (key, value) in re.findall(r'([a-zA-Z0-9]+):\s*"([^"]+)"', raw_client):
                if key == 'AvgRssi0':
                    client['signal'] = int(value)
                elif key == 'bw':
                    client['bandwidth'] = value
                elif key == 'mac':
                    client['mac'] = value.lower()
            clients[client.pop('mac')] = client
        return clients

    @staticmethod
    def parse_client_dhcp_leases(data, clients):
        # 1617591671 5c:51:4f:f7:21:cd 192.168.1.55 TATIANKA-X240 01:5c:51:4f:f7:21:cd
        for line in data.splitlines():
            match = re.match(r'^([0-9]+)\s+([0-9a-fA-F:]{17})\s+(\S+)\s+(\S+)\s+.*$', line)
            if match and match.group(2) in clients:
                clients[match.group(2)]['ip'] = match.group(3)
                if 4 == len(match.groups()):
                    clients[match.group(2)]['name'] = match.group(4)

    exclude = []
    include = []

    def __init__(self, config):
        self.last_results = []
        self.last_results_names = {}

        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.exclude = config[CONF_EXCLUDE]
        self.include = config[CONF_INCLUDE]
        self.read_timeout = config[CONF_READ_TIMEOUT].total_seconds()

        self.success_init = self._update_info()
        _LOGGER.debug('Scanner initialized')

    def read_output(self, tn: telnetlib.Telnet):
        return tn.read_until(PROMPT, timeout=self.read_timeout).decode('utf-8')

    def scan_devices(self):
        self._update_info()
        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        return self.last_results_names.get(device, None)

    def get_extra_attributes(self, device):
        filter_att = next((
            {
                'signal': result.signal,
                'bandwidth': result.bandwidth,
                'interface': result.interface,
                'ip': result.ip
            } for result in self.last_results if result.mac == device), None)
        return filter_att

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        _LOGGER.debug('Scanning...')

        clients = {}
        exclude_hosts = self.exclude
        include_hosts = self.include

        """ignore exclude if include present"""
        if include_hosts:
            exclude_hosts = []

        try:
            with telnetlib.Telnet(self.host, 23, timeout=self.read_timeout) as tn:
                tn.read_until(b'login: ')
                tn.write(self.username.encode('ascii') + b'\n')
                tn.read_until(b'Password: ')
                tn.write(self.password.encode('ascii') + b'\n')
                tn.read_until(PROMPT, timeout=self.read_timeout)

                tn.write(b'luci-stainfo ra0\n')
                clients = self.parse_clients(self.read_output(tn), '2.4GHz')

                tn.write(b'luci-stainfo rai0\n')
                clients.update(self.parse_clients(self.read_output(tn), '5GHz'))

                tn.write(b'cat /tmp/dhcp.leases\n')
                self.parse_client_dhcp_leases(self.read_output(tn), clients)
                tn.write(b'exit\n')

        except (OSError, EOFError) as e:
            _LOGGER.error('Failed to scan devices: %s', e)
            return False

        last_results = []
        last_results_names = {}
        for mac, client_data in clients.items():
            if 'ip' not in client_data:
                continue

            ip = client_data['ip']
            name = client_data.get('name', None)
            if include_hosts:
                if ip not in include_hosts:
                    _LOGGER.debug('Excluded %s (by IP)', ip)
                    continue

                if name and name not in include_hosts:
                    _LOGGER.debug('Excluded %s (by name)', name)
                    continue

            if exclude_hosts:
                if ip in exclude_hosts:
                    _LOGGER.debug('Excluded %s (by IP)', ip)
                    continue

                if name and name in exclude_hosts:
                    _LOGGER.debug('Excluded %s (by name)', ip)
                    continue

            last_results.append(Device(mac, client_data['signal'], client_data['bandwidth'],
                client_data['interface'], ip))

            if name:
                last_results_names[mac] = name

        self.last_results = last_results
        self.last_results_names = last_results_names

        _LOGGER.debug('Scan succesful')
        return True
