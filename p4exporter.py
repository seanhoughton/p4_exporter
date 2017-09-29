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

REPLICA_TYPES = ('replica', 'forwarding-replica', 'standby', 'forwarding-standby', 'edge-server')

LOGIN_TIMEOUT = 5
COLLECTION_TIMEOUT = 15

class P4Collector(object):

    def __init__(self, port, user, password, collectors):
        self.port = port
        self.user = user
        self.password = password
        self.collectors = collectors

        self.collected_ports = set()

        self.up_gauge = GaugeMetricFamily('p4_up', 'Server is up', labels=['server_id'])
        self.alive_guage = GaugeMetricFamily('p4_alive', 'Server is actively replicating', labels=['server_id'])
        self.uptime_counter = CounterMetricFamily('p4_uptime', 'Uptime in seconds for the server process', labels=['server_id'])
        self.response_time_guage = GaugeMetricFamily('p4_response_time', 'Seconds to get p4 info', labels=['server_id'])

        self.monitor_guages = {}
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

    async def monitor(self, p4, server_id, log):
        def time_to_seconds(time_string):
            h, m, s = time_string.split(':')
            return int(h) * 3600 + int(m) * 60 + int(s)
        log.debug('Inspecting processes')
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
            log.error('Failed to get monitor stats: %s', e)

    async def changelist(self, p4, server_id, log):
        log.debug('Inspecting changelist...')
        changelist, = await p4.run_counter('change')
        self.changelist_guage.add_metric([server_id], int(changelist['value']))

    async def workspaces(self, p4, server_id, log):
        log.debug('Inspecting workspaces...')
        clients = await p4.run_clients()
        self.workspaces_guage.add_metric([server_id], len(clients))

    async def users(self, p4, server_id, log):
        log.debug('Inspecting users...')
        users = await p4.run_users()
        self.users_guage.add_metric([server_id], len(users))

    async def journal_replication(self, p4, server_id, log):
        log.debug('Inspecting journal replication...')
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
            log.error('Failed to get journal replication stats: %s', e)

    async def file_replication(self, p4, server_id, log):
        log.debug('Inspecting file replication...')
        try:
            pull, = await p4.run_pull('-l', '-s')
            self.pull_replica_transfers_active.add_metric([server_id], float(pull['replicaTransfersActive']))
            self.pull_replica_transfers_total.add_metric([server_id], float(pull['replicaTransfersTotal']))
            self.pull_replica_bytes_active.add_metric([server_id], float(pull['replicaBytesActive']))
            self.pull_replica_bytes_total.add_metric([server_id], float(pull['replicaBytesTotal']))
            if 'replicaOldestChange' in pull:
                self.pull_replica_oldest_change.add_metric([server_id], float(pull['replicaOldestChange']))
        except Exception as e:
            logging.error('Failed to get file replication stats: %s', e)

    async def depots(self, p4, server_id, log):
        log.debug('Inspecting depots...')
        depots = await p4.run_depots()
        for depot in depots:
            depot_name = depot['name']
            depot_type = depot['type']
            log.debug('Inspecting depot %s...', depot_name)
            size_info = await p4.run_sizes('-a', '-z', '//{}/...'.format(depot_name))[0]
            self.depot_size_guage.add_metric([server_id, depot_name, depot_type], int(size_info['fileSize']))
            self.depot_count_guage.add_metric([server_id, depot_name, depot_type], int(size_info['fileCount']))
            self.depot_created_guage.add_metric([server_id, depot_name, depot_type], int(depot['time']))

    async def collect_from(self, port, server_id, is_alive, id_to_addr):
        try:
            # Prevent duplicate collection caused by multiple server records with the same ExternalAddress
            log = logging.getLogger(port)
            if port in self.collected_ports:
                log.info('Skipping collection, already collected.')
                return

            self.alive_guage.add_metric([server_id], int(is_alive))
            if not is_alive:
                log.info('Skipping collection, not alive')
                return

            self.collected_ports.add(port)

            log.info('Starting collection...')
            try:
                p4 = P4(port=port, user=self.user, password=self.password, exception_level=1, prog='prometheus-p4-metrics')
                start_time = time.time()
                info, = await p4.run_info()
                info_time = time.time() - start_time
            except Exception as e:
                self.up_gauge.add_metric([server_id], 0)
                log.error('Failed to connect')
                return

            self.up_gauge.add_metric([server_id], 1)
            self.response_time_guage.add_metric([server_id], info_time)
            self.uptime(info, server_id)

            try:
                await asyncio.wait_for(p4.run_login(), LOGIN_TIMEOUT)
            except asyncio.TimeoutError:
                log.error('Timed out logging in')
                return

            tasks = []
            tasks.append(self.monitor(p4, server_id, log))
            tasks.append(self.changelist(p4, server_id, log))

            if 'replication' in self.collectors:
                if info['serverServices'] in REPLICA_TYPES:
                   tasks.append(self.journal_replication(p4, server_id, log))
                if 'lbr.replication' in info and info['lbr.replication'] != 'shared':
                    tasks.append(self.file_replication(p4, server_id, log))
            if 'workspaces' in self.collectors:
                tasks.append(self.workspaces(p4, server_id, log))
            if 'users' in self.collectors:
                tasks.append(self.users(p4, server_id, log))
            if 'depots' in self.collectors:
                tasks.append(self.depots)

            log.info('Starting gathering metrics...')
            results = await asyncio.gather(*tasks)
            log.info('Completed gathering metrics')
            
            if info['serverServices'] in ('commit-server', 'edge-server'):
                log.info('Loading replica list...')
                replicas = [server for server in await p4.run_servers('-J') if server['ServerID'] != server_id]
                if replicas:
                    log.info('Found %d replicas', len(replicas))
                    replica_tasks = [self.collect_from(id_to_addr[s['ServerID']], s['ServerID'], s['IsAlive'], id_to_addr) for s in replicas]
                    await asyncio.gather(*replica_tasks)
            log.info('Done')
        except Exception as e:
            log.exception('Failed to gather metrics')
  

    async def collect(self):
        try:
            p4 = P4(port=self.port, user=self.user, password=self.password, exception_level=1, prog='prometheus-p4-metrics')
            info, = await p4.run_info()
            if info['serverServices'] != 'commit-server':
                logging.error('Target must be a commit server')
                return

            await p4.run_login()
        except Exception as e:
            logging.error('Failed to log in to %s as %s: %s', self.port, self.user, e)

        # Build a list of servers and a map from serverid to p4port
        id_to_addr = {server['ServerID']: server['ExternalAddress'] for server in await p4.run_servers() if 'ExternalAddress' in server}

        # Start the collection process with the P4PORT provded, should be the commit server
        await asyncio.wait_for(self.collect_from(self.port, info['ServerID'], True, id_to_addr), COLLECTION_TIMEOUT)
        logging.info('All collection complete.')

        # Yield all the metric families
        for field in self.__dict__.values():
            if isinstance(field, GaugeMetricFamily) or isinstance(field, CounterMetricFamily):
                yield field
        logging.info('Metric iteration complete.')
        

class RegistryWrapper(object):
    def __init__(self, metrics):
        self.metrics = metrics

    def collect(self):
        return self.metrics


async def handle(port, user, password, collectors, request):
    logging.info('Got request...')
    collector = P4Collector(port, user, password, collectors)
    metrics = []
    try:
        async for metric in collector.collect():
            metrics.append(metric)
    except asyncio.TimeoutError:
        logging.error('Timed out waiting for metrics')
        return web.Response(text='Timed out gathering metrics for %s' % port, status=408)
    registry = RegistryWrapper(metrics)
    return web.Response(text=generate_latest(registry).decode('utf-8'), headers={'Content-Type': CONTENT_TYPE_LATEST})

def enable_debug():
    import warnings
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.slow_callback_duration = 0.1
    warnings.simplefilter('always', ResourceWarning)

    #import ptvsd
    #ptvsd.enable_attach("my_secret", address = ('0.0.0.0', 3500))
    #logging.info('Waiting for debugger to attach on port 3500')        
    #ptvsd.wait_for_attach()


def run(options):
    if options.debug:
        enable_debug()
    app = web.Application()
    handler = partial(handle, options.p4port, options.p4user, options.p4passwd, options.collectors.split(','))
    app.router.add_get('/metrics', handler)
    web.run_app(app, port=options.port)


def main():
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False, help='Enable verbose logging')
    parser.add_argument('-p', '--port', dest='port', type=int, default=9666, help='The port to expose metrics on, default: 9666')
    parser.add_argument('--p4port', default=os.environ.get('P4PORT', ''), help='P4PORT of the commit server in a cluster')
    parser.add_argument('--p4user', default=os.environ.get('P4USER', ''), help='P4USER to log in with')
    parser.add_argument('--p4passwd', default=os.environ.get('P4PASSWD', ''), help='P4PASSWD to log in with, ideally with a long ticket expiry')
    parser.add_argument('--collectors', default=os.environ.get('COLLECTORS', 'replication,workspaces,users'), help='Comma delimited list of collectors')
    parser.add_argument('--debug', action='store_true', help='Enable VSCode debugging')
    options = parser.parse_args()
    log_format='%(asctime)s %(name)-40s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.DEBUG if options.verbose else logging.INFO, format=log_format)
    logging.info('Listening on port :%d...', options.port)
    run(options)


if __name__ == '__main__':
    main()

