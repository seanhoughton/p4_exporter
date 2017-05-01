#!/usr/bin/env python

import os
import yaml
from argparse import ArgumentParser
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
import time
import logging
from P4 import P4
from collections import defaultdict
import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ForkingMixIn
import traceback


COMMAND_STATES = {
    'R': 'running',
    'T': 'terminated',
    'P': 'paused',
    'B': 'background',
    'F': 'finished',
    'I': 'idle'
}

class P4Collector(object):

    def __init__(self):
        self.params = {}
        self.config = {}

    def connection(self, p4port):
        p4 = P4(exception_level=1, prog='prometheus-p4-metrics')
        hostname, port = p4port.split(':')
        credentials = self.config.get('credentials', {}).get(p4port, None)
        if credentials:
            p4.user = credentials['username']
            p4.password = credentials['password']
        else:
            logging.warning('No credentials for %s', p4port)
        p4.port = p4port
        try:
            logging.info('Connecting to %s...', p4port)
            p4.connect()
            if credentials:
                try:
                    logging.debug('Logging in as to "%s@%s"...', p4port, p4.user)
                    p4.run_login()
                    logging.debug('Conected and logged in.')
                except Exception as e:
                    logging.error('Failed to log in to %s: %s', p4port, e)
                    credentials = None
                return (p4, credentials is not None)
        except Exception as e:
            logging.error('Failed to connect to %s: %s', p4port, e)
            return (None, False)

    def name(self, name):
        return 'p4_' + name

    def uptime(self, info):
        values = info['serverUptime'].split(':')
        uptime = int(values[0]) * 3600 + int(values[1]) * 60 + int(values[2])
        family = CounterMetricFamily(self.name('uptime'), 'Uptime in seconds for the server process', labels=[])
        family.add_metric([], uptime)
        return family

    def monitor(self, p4):
        def time_to_seconds(time_string):
            h, m, s = time_string.split(':')
            return int(h) * 3600 + int(m) * 60 + int(s)
        logging.debug('Inspecting processes')
        try:
            commands = p4.run_monitor('show')
            for code, state in COMMAND_STATES.items():
                cur_commands = [command for command in commands if command['status'] == code]
                yield GaugeMetricFamily(name=self.name('commands_{}_count'.format(state)),
                                        documentation='Number of commands in the {} state'.format(state),
                                        value=len(cur_commands))
                yield GaugeMetricFamily(name=self.name('commands_{}_users'.format(state)),
                                        documentation='Number of users running commands in the {} state'.format(state),
                                        value=len(set([item['user'] for item in cur_commands])))
                if cur_commands:
                    times = [time_to_seconds(command['time']) for command in cur_commands]
                    yield GaugeMetricFamily(name=self.name('commands_{}_time_min'.format(state)),
                                            documentation='Minimum time for commands in the {} state'.format(state),
                                            value=min(times))
                    yield GaugeMetricFamily(name=self.name('commands_{}_time_max'.format(state)),
                                            documentation='Maximum time for commands in the {} state'.format(state),
                                            value=max(times))
                    yield GaugeMetricFamily(name=self.name('commands_{}_time_avg'.format(state)),
                                            documentation='Average time for commands in the {} state'.format(state),
                                            value=float(sum(times)) / float(len(times)))
        except Exception as e:
            logging.error('Failed to get monitor stats: %s', e)

    def changelist(self, p4):
        logging.debug('Inspecting changelist...')
        changelist = p4.run_counter('change')[0]
        return GaugeMetricFamily(self.name('changelist'), 'Current head changelist', value=int(changelist['value']))

    def workspaces(self, p4):
        logging.debug('Inspecting workspaces...')
        clients = p4.run_clients()
        return GaugeMetricFamily(self.name('workspaces'), 'Number of active workspaces', value=len(clients))

    def users(self, p4):
        logging.debug('Inspecting users...')
        users = p4.run_users()
        return GaugeMetricFamily(self.name('users'), 'Number of active users', value=len(users))

    def journal_replication(self, p4):
        logging.debug('Inspecting journal replication...')
        try:
            pull = p4.run_pull('-lj').pop()
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
            pull = p4.run_pull('-l', '-s').pop()
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
        depots = p4.run_depots()
        for depot in depots:
            depot_name = depot['name']
            depot_type = depot['type']
            logging.debug('Inspecting depot %s...', depot_name)
            size_info = p4.run_sizes('-a', '-z', '//{}/...'.format(depot_name))[0]
            size_guage.add_metric([depot_name, depot_type], int(size_info['fileSize']))
            count_guage.add_metric([depot_name, depot_type], int(size_info['fileCount']))
            created_guage.add_metric([depot_name, depot_type], int(depot['time']))
        return size_guage, count_guage, created_guage

    def collect(self):
        p4port = self.params['target'][0]
        p4, is_logged_in = self.connection(p4port)
        if not p4:
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=0)
            return

        with p4:
            if not p4.connected():
                try:
                    p4.connect()
                except Exception as e:
                    logging.info('Failed to re-connect an existing connection')
                    yield GaugeMetricFamily(self.name('up'), 'Server is up', value=0)
                    return

            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=1)

            if not is_logged_in:
                return

            start_time = time.time()
            info = p4.run_info()[0]
            info_time = time.time() - start_time
            yield GaugeMetricFamily(self.name('response_time'), 'Seconds to get p4 info', value=info_time)
            yield self.uptime(info)

            yield from self.monitor(p4)
            yield self.changelist(p4)

            extra_collectors = set(self.params['collectors'][0].split(',')) if 'collectors' in self.params else set()
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

            logging.debug('Disconnecting...')
            p4.disconnect(). # explicitly disconnect


class ForkingHTTPServer(ForkingMixIn, HTTPServer):
    pass


class P4ExporterHandler(BaseHTTPRequestHandler):
    def __init__(self, config_path, *args, **kwargs):
        self._config_path = config_path
        try:
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
        except Exception as e:
            logging.exception('Failed to handle request: %s', e)

    def collect(self, params):
        with open(self._config_path, 'r') as f:
            config = yaml.safe_load(f)
        collector = P4Collector()
        collector.config = config
        collector.params = params
        registry = CollectorRegistry()
        registry.register(collector)
        return generate_latest(registry)

    def do_GET(self):
        logging.info('Got request...')
        url = urlparse.urlparse(self.path)
        if url.path == '/metrics':
          params = urlparse.parse_qs(url.query)
          if 'target' not in params:
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Missing 'target' from parameters")
            return

          try:
            output = self.collect(params)
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
          except Exception as e:
            logging.error('Internal error: %s', e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(traceback.format_exc())

        elif url.path == '/':
          self.send_response(200)
          self.end_headers()
          self.wfile.write(str.encode("""<html>
          <head><title>P4 Exporter</title></head>
          <body>
          <h1>P4 Exporter</h1>
          <p>Visit <code>/metrics?target=perforce:1666</code> to use.</p>
          </body>
          </html>"""))
        else:
          self.send_response(404)
          self.end_headers()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=True, help='Enable verbose logging')
    parser.add_argument('-p', '--port', dest='port', type=int, default=9666, help='The port to expose metrics on, default: 9666')
    parser.add_argument('-c', '--config', dest='config', default='/etc/p4_exporter/conf.yml', help='Path to the configuration file')
    options = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if options.verbose else logging.INFO, format='[%(levelname)s] %(message)s')
    logging.info('Listening on port :%d...', options.port)
    handler = lambda *args, **kwargs: P4ExporterHandler(options.config, *args, **kwargs)
    server = ForkingHTTPServer(('', options.port), handler)
    server.serve_forever()
