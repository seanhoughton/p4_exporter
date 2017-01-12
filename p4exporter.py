from argparse import ArgumentParser
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
import time
from P4 import P4


def debug(result):
    for key in result:
        print key, "=", result[key]


class P4Collector(object):

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

    def collect(self):
        p4 = P4()
        try:
            start_time = time.time()
            p4.connect()
            connect_time = time.time() - start_time
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=1)
        except:
            yield GaugeMetricFamily(self.name('up'), 'Server is up', value=0)
            return
        yield GaugeMetricFamily(self.name('connect_time'), 'Seconds to establish a connection', value=connect_time)
        yield self.uptime(p4)
        yield self.workspaces(p4)
        yield self.users(p4)
        yield self.changelist(p4)
        depot_sizes, depot_counts, created_guage = self.depot_guages(p4)
        yield depot_sizes
        yield depot_counts
        yield created_guage


if __name__ == '__main__':
    parser = ArgumentParser()
    #parser.add_argument('--spec', dest='specs', action='append', help='Filespec for detailed stats')
    options = parser.parse_args()
    REGISTRY.register(P4Collector())
    start_http_server(8666)
    while True:
        time.sleep(5)
