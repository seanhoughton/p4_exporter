#!/usr/bin/env python

import os
import re
import yaml
from argparse import ArgumentParser
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
import time
import logging
from P4 import P4


class P4Collector(object):

    def __init__(self, config):
        self.config = config

    def name(self, name):
        return 'p4_' + name

    def uptime(self, info):
        values = info['serverUptime'].split(':')
        uptime = int(values[0]) * 3600 + int(values[1]) * 60 + int(values[2])
        family = CounterMetricFamily(self.name('uptime'), 'Uptime in seconds for the server process', labels=[])
        family.add_metric([], uptime)
        return family

    def changelist(self, p4):
        logging.debug('Inspecting changelist...')
        changelist = p4.run(['counter', 'change'])[0]
        return GaugeMetricFamily(self.name('changelist'), 'Current head changelist', value=int(changelist['value']))

    def workspaces(self, p4):
        logging.debug('Inspecting workspaces...')
        clients = p4.run('clients')
        return GaugeMetricFamily(self.name('workspaces'), 'Number of active workspaces', value=len(clients))

    def users(self, p4):
        logging.debug('Inspecting users...')
        users = p4.run('users')
        return GaugeMetricFamily(self.name('users'), 'Number of active users', value=len(users))

    def journal_replication(self, p4):
        logging.debug('Inspecting journal replication...')
        try:
            pull = p4.run(['pull', '-lj']).pop()
            yield CounterMetricFamily(self.name('pull_replica_journal_sequence'), 'Replica journal sequence', value=float(pull['replicaJournalSequence']))
            yield CounterMetricFamily(self.name('pull_replica_journal_counter'), 'Replica journal counter', value=float(pull['replicaJournalCounter']))
            yield CounterMetricFamily(self.name('pull_replica_journal_number'), 'Replica journal number', value=float(pull['replicaJournalNumber']))
            yield CounterMetricFamily(self.name('pull_master_journal_sequence'), 'Master journal sequence', value=float(pull['masterJournalSequence']))
            yield CounterMetricFamily(self.name('pull_master_journal_number'), 'Master journal number', value=float(pull['masterJournalNumber']))
            yield CounterMetricFamily(self.name('pull_replica_time'), 'Replica Timestamp', value=float(pull['replicaTime']))
            yield CounterMetricFamily(self.name('pull_replica_statefile_modified'), 'Replica statefile modified timestamp', value=float(pull['replicaStatefileModified']))
        except Exception as e:
            logging.error('Failed to get journal replication stats: %s', e)

    def file_replication(self, p4):
        logging.debug('Inspecting file replication...')
        try:
            pull = p4.run(['pull', '-l', '-s']).pop()
            yield GaugeMetricFamily(self.name('pull_replica_transfers_active'), 'Replica file transfers active', value=float(pull['replicaTransfersActive']))
            yield GaugeMetricFamily(self.name('pull_replica_transfers_total'), 'Replica total transfers', value=float(pull['replicaTransfersTotal']))
            yield GaugeMetricFamily(self.name('pull_replica_bytes_active'), 'Replica bytes active', value=float(pull['replicaBytesActive']))
            yield GaugeMetricFamily(self.name('pull_replica_bytes_total'), 'Replica bytes total', value=float(pull['replicaBytesTotal']))
            yield CounterMetricFamily(self.name('pull_replica_oldest_change'), 'Replica oldest change', value=float(pull['replicaOldestChange']))
        except Exception as e:
            logging.error('Failed to get file replication stats: %s', e)

    def depot_guages(self, p4):
        logging.debug('Inspecting depots...')
        size_guage = GaugeMetricFamily(self.name('depot_size'), 'Size of a depot in bytes', labels=['depot', 'type'])
        count_guage = GaugeMetricFamily(self.name('depot_files'), 'Number of files in a depot', labels=['depot', 'type'])
        created_guage = GaugeMetricFamily(self.name('depot_created'), 'Creation time of the depot', labels=['depot', 'type'])
        depots = p4.run(['depots'])
        for depot in depots:
            depot_name = depot['name']
            depot_type = depot['type']
            logging.debug('Inspecting depot %s...', depot_name)
            size_info = p4.run(['sizes', '-a', '-z', '//{}/...'.format(depot_name)])[0]
            size_guage.add_metric([depot_name, depot_type], int(size_info['fileSize']))
            count_guage.add_metric([depot_name, depot_type], int(size_info['fileCount']))
            created_guage.add_metric([depot_name, depot_type], int(depot['time']))
        return size_guage, count_guage, created_guage

    def collect(self, params):
        if not params:
            return
        p4 = P4()
        p4.exception_level = 1
        p4port = params['target'][0]
        hostname, port = p4port.split(':')
        credentials = self.config.get('credentials', {}).get(p4port, None)
        if credentials:
            p4.user = credentials['username']
            p4.password = credentials['password']
        p4.port = p4port

        try:
            logging.info('Connecting to %s...', p4port)
            start_time = time.time()
            p4.connect()
            connect_time = time.time() - start_time
        except Exception as e:
            logging.error('Failed to connect to %s: %s', p4port, e)
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=0)
            return

        yield GaugeMetricFamily(self.name('up'), 'Server is up', value=1)
        yield GaugeMetricFamily(self.name('connect_time'), 'Seconds to establish a connection', value=connect_time)

        if not credentials:
            logging.warning('No credentials for %s', p4port)
            return

        try:
            logging.debug('Logging in...')
            p4.run_login()
            logging.debug('Conected and logged in.')
        except Exception as e:
            logging.error('Failed to log in to %s: %s', p4port, e)
            return

        info = p4.run("info")[0]
        yield self.uptime(info)
        yield self.changelist(p4)

        extra_collectors = set(params['collectors'][0].split(',')) if 'collectors' in params else set()
        if 'replication' in extra_collectors:
            if info['serverServices'] in ('replica', 'forwarding-replica', 'edge-server'):
                yield from self.journal_replication(p4)
            if 'lbr.replication' in info and info['lbr.replication'] != 'shared':
                yield from self.file_replication(p4)
        if 'workspaces' in extra_collectors:
            yield self.workspaces(p4)
        if 'users' in extra_collectors:
            yield self.users(p4)
        if 'depots' in extra_collectors:
            depot_sizes, depot_counts, created_guage = self.depot_guages(p4)
            yield depot_sizes
            yield depot_counts
            yield created_guage
        p4.disconnect()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=True, help='Enable verbose logging')
    parser.add_argument('-p', '--port', dest='port', type=int, default=9666, help='The port to expose metrics on, default: 9666')
    parser.add_argument('-c', '--config', dest='config', default='/etc/p4_exporter/conf.yml', help='Path to the configuration file')
    options = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if options.verbose else logging.INFO, format='[%(levelname)s] %(message)s')
    logging.info('Creating collector...')
    if os.path.isfile(options.config):
        config = yaml.load(open(options.config, 'r'))
    else:
        logging.warning("Config file %s does not exist, no credentials loaded.", options.config)
        config = {}
    REGISTRY.register(P4Collector(config))
    logging.info('Listening on port :%d...', options.port)
    start_http_server(options.port)
    while True:
        time.sleep(5)
