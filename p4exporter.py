#!/usr/bin/env python

import os
import re
from argparse import ArgumentParser
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
import time
import logging
from P4 import P4


CREDENTIAL_REGEX = r'(?P<username>.+)\:(?P<password>.+)\@(?P<hostname>.+)'


class P4Collector(object):

    def __init__(self, credentials):
        parsed_credentials = [re.match(CREDENTIAL_REGEX, c).groupdict() for c in credentials.split(',')]
        self.credentials = {self.credential_key(c['hostname'], c['username']): c['password'] for c in parsed_credentials}
        logging.info("Loaded %d credential", len(self.credentials))

    def credential_key(self, hostname, username):
        return '%s-%s' % (username, hostname)

    def name(self, name):
        return 'p4_' + name

    def uptime(self, p4):
        info = p4.run("info")[0]
        values = info['serverUptime'].split(':')
        uptime = int(values[0]) * 3600 + int(values[1]) * 60 + int(values[2])
        family = CounterMetricFamily(self.name('uptime'), 'Uptime in seconds for the server process', labels=[])
        family.add_metric([], uptime)
        return family

    def changelist(self, p4):
        changelist = p4.run(['counter', 'change'])[0]
        return GaugeMetricFamily(self.name('changelist'), 'Current head changelist', value=int(changelist['value']))

    def workspaces(self, p4):
        clients = p4.run('clients')
        return GaugeMetricFamily(self.name('workspaces'), 'Number of active workspaces', value=len(clients))

    def users(self, p4):
        users = p4.run('users')
        return GaugeMetricFamily(self.name('users'), 'Number of active users', value=len(users))

    def depot_guages(self, p4):
        size_guage = GaugeMetricFamily(self.name('depot_size'), 'Size of a depot in bytes', labels=['depot', 'type'])
        count_guage = GaugeMetricFamily(self.name('depot_files'), 'Number of files in a depot', labels=['depot', 'type'])
        created_guage = GaugeMetricFamily(self.name('depot_files'), 'Number of files in a depot', labels=['depot', 'type'])
        depots = p4.run(['depots'])
        for depot in depots:
            depot_name = depot['name']
            depot_type = depot['type']
            size_info = p4.run(['sizes', '-a', '-z', '//{}/...'.format(depot_name)])[0]
            size_guage.add_metric([depot_name, depot_type], int(size_info['fileSize']))
            count_guage.add_metric([depot_name, depot_type], int(size_info['fileCount']))
            created_guage.add_metric([depot_name, depot_type], int(depot['time']))
        return size_guage, count_guage, created_guage

    def collect(self, params):
        if not params:
            return
        p4 = P4()
        hostname, port = params['port'][0].split(':')
        username = params['username'][0]
        p4.user = username
        p4.port = params['port'][0]
        credential_key = self.credential_key(hostname, username)
        if credential_key not in self.credentials:
            logging.error('No credentials for %s@%s', username, hostname)
            return
        p4.password = self.credentials[credential_key]
        try:
            start_time = time.time()
            logging.debug('Connecting to %s@%s...', params['username'][0], params['port'][0])
            p4.connect()
            p4.run_login()
            logging.debug('Conected.')
            connect_time = time.time() - start_time
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=1)
        except Exception as e:
            logging.error('Failed to connect: %s', e)
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=0)
            return
        yield GaugeMetricFamily(self.name('connect_time'), 'Seconds to establish a connection', value=connect_time)
        yield self.uptime(p4)
        yield self.workspaces(p4)
        yield self.users(p4)
        yield self.changelist(p4)
        #depot_sizes, depot_counts, created_guage = self.depot_guages(p4)
        #yield depot_sizes
        #yield depot_counts
        #yield created_guage


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False, help='Enable verbose logging')
    parser.add_argument('-p', '--port', dest='port', type=int, default=9666, help='The port to expose metrics on, default: 9666')
    parser.add_argument('-c', '--credentials', dest='credentials', default=os.environ.get('P4EXP_CREDENTIALS', ''), help='A command delimited set of credentials in <username>:<password>@<hostname> format.')
    options = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if options.verbose else logging.INFO, format='[%(levelname)s] %(message)s')
    logging.info('Creating collector...')
    REGISTRY.register(P4Collector(options.credentials))
    logging.info('Listening on port :%d...', options.port)
    start_http_server(options.port)
    while True:
        time.sleep(5)
