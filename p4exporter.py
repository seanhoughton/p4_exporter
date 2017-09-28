import time
import logging
import os
import asyncio
from functools import partial
from argparse import ArgumentParser
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from aiop4 import AsyncP4 as P4
from aiohttp import web


TIMEOUT = 10

COMMAND_STATES = {
    'R': 'running',
    'T': 'terminated',
    'P': 'paused',
    'B': 'background',
    'F': 'finished',
    'I': 'idle'
}


class P4Collector(object):

    def __init__(self, port, user, collectors):
        self.port = port
        self.user = user
        self.collectors = collectors
        self.monitor_guages = {}

        self.up_guage = GaugeMetricFamily('p4_up', 'Server is up', labels=['server_id'])
        self.uptime_counter = CounterMetricFamily('p4_uptime', 'Uptime in seconds for the server process', labels=['server_id'])
        self.response_time_guage = GaugeMetricFamily('p4_response_time', 'Seconds to get p4 info', labels=['server_id'])

        for code, state in COMMAND_STATES.items():
            count_name = 'p4_commands_{}_count'.format(state)
            self.monitor_guages[count_name] = GaugeMetricFamily(name=count_name,
                                                                documentation='Number of commands in the {} state'.format(state),
                                                                labels=['server_id'])

            users_name = 'p4_commands_{}_users'.format(state)
            self.monitor_guages[users_name] = GaugeMetricFamily(name=users_name,
                                                                documentation='Number of users running commands in the {} state'.format(state),
                                                                labels=['server_id'])

            min_time_name = 'p4_commands_{}_time_min'.format(state)
            self.monitor_guages[min_time_name] = GaugeMetricFamily(name=min_time_name,
                                                                   documentation='Minimum time for commands in the {} state'.format(state),
                                                                   labels=['server_id'])

            max_time_name = 'p4_commands_{}_time_max'.format(state)
            self.monitor_guages[max_time_name] = GaugeMetricFamily(name=max_time_name,
                                                                   documentation='Maximum time for commands in the {} state'.format(state),
                                                                   labels=['server_id'])

            avg_time_name = 'p4_commands_{}_time_avg'.format(state)
            self.monitor_guages[avg_time_name] = GaugeMetricFamily(name=avg_time_name,
                                                                   documentation='Average time for commands in the {} state'.format(state),
                                                                   labels=['server_id'])


        self.changelist_guage = GaugeMetricFamily('p4_changelist', 'Current head changelist', labels=['server_id'])
        self.workspaces_guage = GaugeMetricFamily('p4_workspaces', 'Number of active workspaces', labels=['server_id'])
        self.users_guage = GaugeMetricFamily('p4_users', 'Number of active users', labels=['server_id'])
        self.pull_replica_journal_sequence = CounterMetricFamily('p4_pull_replica_journal_sequence', 'Replica journal sequence', labels=['server_id'])
        self.pull_replica_journal_counter = CounterMetricFamily('p4_pull_replica_journal_counter', 'Replica journal counter', labels=['server_id'])
        self.pull_replica_journal_number = CounterMetricFamily('p4_pull_replica_journal_number', 'Replica journal number', labels=['server_id'])
        self.pull_master_journal_sequence = CounterMetricFamily('p4_pull_master_journal_sequence', 'Master journal sequence', labels=['server_id'])
        self.pull_master_journal_number = CounterMetricFamily('p4_pull_master_journal_number', 'Master journal number', labels=['server_id'])
        self.pull_replica_time = CounterMetricFamily('p4_pull_replica_time', 'Replica Timestamp', labels=['server_id'])
        self.pull_replica_statefile_modified = CounterMetricFamily('p4_pull_replica_statefile_modified', 'Replica statefile modified timestamp', labels=['server_id'])
        self.pull_replica_transfers_active = GaugeMetricFamily('p4_pull_replica_transfers_active', 'Replica file transfers active', labels=['server_id'])
        self.pull_replica_transfers_total = GaugeMetricFamily('p4_pull_replica_transfers_total', 'Replica total transfers', labels=['server_id'])
        self.pull_replica_bytes_active = GaugeMetricFamily('p4_pull_replica_bytes_active', 'Replica bytes active', labels=['server_id'])
        self.pull_replica_bytes_total = GaugeMetricFamily('p4_pull_replica_bytes_total', 'Replica bytes total', labels=['server_id'])
        self.pull_replica_oldest_change = CounterMetricFamily('p4_pull_replica_oldest_change', 'Replica oldest change', labels=['server_id'])
        self.depot_size_guage = GaugeMetricFamily('p4_depot_size', 'Size of a depot in bytes', labels=['server_id', 'depot', 'type'])
        self.depot_count_guage = GaugeMetricFamily('p4_depot_files', 'Number of files in a depot', labels=['server_id', 'depot', 'type'])
        self.depot_created_guage = GaugeMetricFamily('p4_depot_created', 'Creation time of the depot', labels=['server_id', 'depot', 'type'])


    def uptime(self, info, server_id):
        values = info['serverUptime'].split(':')
        uptime = int(values[0]) * 3600 + int(values[1]) * 60 + int(values[2])
        family = CounterMetricFamily('p4_uptime', 'Uptime in seconds for the server process', labels=['server_id'])
        family.add_metric([server_id], uptime)
        return family

    async def monitor(self, p4, server_id):
        def time_to_seconds(time_string):
            h, m, s = time_string.split(':')
            return int(h) * 3600 + int(m) * 60 + int(s)
        logging.debug('Inspecting processes')
        try:
            commands = await p4.run_monitor('show')
            for code, state in COMMAND_STATES.items():
                cur_commands = [command for command in commands if command['status'] == code]
                self.monitor_guages['p4_commands_{}_count'.format(state)].add_metric([server_id], len(cur_commands))
                self.monitor_guages['p4_commands_{}_users'.format(state)].add_metric([server_id], len(set([item['user'] for item in cur_commands])))
                if cur_commands:
                    times = [time_to_seconds(command['time']) for command in cur_commands]
                    self.monitor_guages['p4_commands_{}_time_min'.format(state)].add_metric([server_id], value=min(times))
                    self.monitor_guages['p4_commands_{}_time_max'.format(state)].add_metric([server_id], max(times))

        except Exception as e:
            logging.error('Failed to get monitor stats: %s', e)

    async def changelist(self, p4, server_id):
        logging.debug('Inspecting changelist...')
        changelist, = await p4.run_counter('change')
        self.changelist_guage.add_metric([server_id], int(changelist['value']))

    async def workspaces(self, p4, server_id):
        logging.debug('Inspecting workspaces...')
        clients = await p4.run_clients()
        self.workspaces_guage.add_metric([server_id], len(clients))

    async def users(self, p4, server_id):
        logging.debug('Inspecting users...')
        users = await p4.run_users()
        self.users_guage.add_metric([server_id], len(users))

    async def journal_replication(self, p4, server_id):
        logging.debug('Inspecting journal replication...')
        try:
            pull, = await p4.run_pull('-lj')
            self.pull_replica_journal_sequence.add_metric([server_id], float(pull['replicaJournalSequence']))
            self.pull_replica_journal_counter.add_metric([server_id], float(pull['replicaJournalCounter']))
            self.pull_replica_journal_number.add_metric([server_id], float(pull['replicaJournalNumber']))
            self.pull_master_journal_sequence.add_metric([server_id], float(pull['masterJournalSequence']))
            self.pull_master_journal_number.add_metric([server_id], float(pull['masterJournalNumber']))
            self.pull_replica_time.add_metric([server_id], float(pull['replicaTime']))
            self.pull_replica_statefile_modified.add_metric([server_id], float(pull['replicaStatefileModified']))
        except Exception as e:
            logging.error('Failed to get journal replication stats: %s', e)

    async def file_replication(self, p4, server_id):
        logging.debug('Inspecting file replication...')
        try:
            pull, = await p4.run_pull('-l', '-s')
            self.pull_replica_transfers_active.add_metric([server_id], float(pull['replicaTransfersActive']))
            self.pull_replica_transfers_total.add_metric([server_id], float(pull['replicaTransfersTotal']))
            self.pull_replica_bytes_active.add_metric([server_id], float(pull['replicaBytesActive']))
            self.pull_replica_bytes_total.add_metric([server_id], float(pull['replicaBytesTotal']))
            self.pull_replica_oldest_change.add_metric([server_id], float(pull['replicaOldestChange']))
        except Exception as e:
            logging.error('Failed to get file replication stats: %s', e)

    async def depots(self, p4, server_id):
        logging.debug('Inspecting depots...')
        depots = await p4.run_depots()
        for depot in depots:
            depot_name = depot['name']
            depot_type = depot['type']
            logging.debug('Inspecting depot %s...', depot_name)
            size_info = await p4.run_sizes('-a', '-z', '//{}/...'.format(depot_name))[0]
            self.depot_size_guage.add_metric([server_id, depot_name, depot_type], int(size_info['fileSize']))
            self.depot_count_guage.add_metric([server_id, depot_name, depot_type], int(size_info['fileCount']))
            self.depot_created_guage.add_metric([server_id, depot_name, depot_type], int(depot['time']))

    async def collect_from(self, port, server_id=None):
        try:
            p4 = P4(port=port, user=self.user, exception_level=1, prog='prometheus-p4-metrics')
            await p4.run_login()
        except Exception as e:
            self.up_gauge.add_metric([''], 0)
            return

        start_time = time.time()
        info, = await p4.run_info()
        logging.info('serverid: %s', info)
        server_id = info['ServerID']
        self.up_guage.add_metric([server_id], 1)

        info_time = time.time() - start_time
        self.response_time_guage.add_metric([server_id], info_time)
        self.uptime(info, server_id)

        tasks = []
        tasks.append(self.monitor(p4, server_id))
        tasks.append(self.changelist(p4, server_id))

        if 'replication' in self.collectors:
            if info['serverServices'] in ('replica', 'forwarding-replica', 'standby', 'forwarding-standby', 'edge-server'):
                tasks.append(self.journal_replication(p4, server_id))
            if 'lbr.replication' in info and info['lbr.replication'] != 'shared':
                tasks.append(self.file_replication(p4, server_id))
        if 'workspaces' in self.collectors:
            tasks.append(self.workspaces(p4, server_id))
        if 'users' in self.collectors:
            tasks.append(self.users(p4, server_id))
        if 'depots' in self.collectors:
            tasks.append(self.depots)

        logging.info('Starting gathering metrics for %s...', port)
        await asyncio.gather(*tasks)
        logging.info('Completed gathering metrics for %s', port)


    async def collect(self):
        await self.collect_from(self.port)
        for field in self.__dict__.values():
            if isinstance(field, GaugeMetricFamily) or isinstance(field, CounterMetricFamily):
                yield field
        

class RegistryWrapper(object):
    def __init__(self, metrics):
        self.metrics = metrics

    def collect(self):
        return self.metrics


async def handle(port, user, collectors, request):
    collector = P4Collector(port, user, collectors)
    metrics = []
    async for metric in collector.collect():
        metrics.append(metric)
    registry = RegistryWrapper(metrics)
    return web.Response(text=generate_latest(registry).decode('utf-8'), headers={'Content-Type': CONTENT_TYPE_LATEST})


def run(options):
    app = web.Application()
    handler = partial(handle, options.p4port, options.p4user, options.collectors.split(','))
    app.router.add_get('/metrics', handler)
    web.run_app(app, port=options.port)


def main():
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=True, help='Enable verbose logging')
    parser.add_argument('-p', '--port', dest='port', type=int, default=9666, help='The port to expose metrics on, default: 9666')
    parser.add_argument('--p4port', default=os.environ.get('P4PORT', ''), help='P4PORT of the commit server in a cluster')
    parser.add_argument('--p4user', default=os.environ.get('P4USER', ''), help='P4USER to log in with')
    parser.add_argument('--p4passwd', default=os.environ.get('P4PASSWD', ''), help='P4PASSWD to log in with, ideally with a long ticket expiry')
    parser.add_argument('--collectors', default=os.environ.get('COLLECTORS', 'replication,workspaces,users'), help='Comma delimited list of collectors')
    options = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if options.verbose else logging.INFO, format='[%(levelname)s] %(name)s %(message)s')
    logging.info('Listening on port :%d...', options.port)
    run(options)


if __name__ == '__main__':
    main()

