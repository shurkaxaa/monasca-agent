#!/bin/env python

# (c) Copyright 2014-2016 Hewlett Packard Enterprise Development LP
# Copyright 2017 Fujitsu LIMITED
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""Monasca Agent interface for libvirt metrics"""

import json
import math
import monasca_agent.collector.checks.utils as utils
import os
import pylxd
import re
import stat
import subprocess
import time
import types

from calendar import timegm
from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from multiprocessing.dummy import Pool
from netaddr import all_matching_cidrs
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as n_client
from novaclient.exceptions import NotFound

from monasca_agent.collector.checks import AgentCheck
from monasca_agent.collector.virt import inspector
from monasca_agent.common import keystone
from monasca_agent import version as ma_version


class LXDInspector(inspector.Inspector):

    def memoryStats(self, container):
        used = container.state().memory['usage'] / 1024
        swap_used = container.state().memory['swap_usage'] / 1024
        # proper parser for MB? how handle unlimited
        total = container.expanded_config['limits.memory']
        total = int(total.split('MB')[0]) * 1024
        return {
            'unused': total - used,
            'swap_out': swap_used,
            'available': total
        }

    def inspect_vnics(self, instance):
        for iface, details in instance.state().network.iteritems():
            hwaddr = details['hwaddr']
            rx_bytes = details['counters']['bytes_received']
            tx_bytes = details['counters']['bytes_sent']
            rx_packets = details['counters']['packets_received']
            tx_packets = details['counters']['packets_sent']
            interface = inspector.Interface(name=iface, mac=hwaddr,
                                            fref='', parameters={})
            stats = inspector.InterfaceStats(rx_bytes=rx_bytes,
                                             rx_packets=rx_packets,
                                             rx_errors=0, rx_dropped=0,
                                             tx_bytes=tx_bytes,
                                             tx_packets=tx_packets,
                                             tx_errors=0, tx_dropped=0)
            yield (interface, stats)

    def inspect_cpus(self, instance):
        # number: number of CPUs
        # time: cumulative CPU time
        try:
            num_cores = int(instance.expanded_config['limits.cpu'])
        except KeyError, ValueError:
            num_cores = 0 # TODO how handle unlimimited?
        return inspector.CPUStats(
            number=num_cores,
            time=instance.state().cpu['usage'])


class LXDCheck(AgentCheck):
    """Inherit Agent class and gather libvirt metrics"""

    OperationCreated = 100
    Started = 101
    Stopped = 102
    Running = 103
    Cancelling = 104
    Pending = 105
    Starting = 106
    Stopping = 107
    Aborting = 108
    Freezing = 109
    Frozen = 110
    Thawed = 111
    Error = 112
    Success = 200
    Failure = 400
    Cancelled = 401

    def __init__(self, name, init_config, agent_config, instances=None):
        AgentCheck.__init__(self, name, init_config, agent_config, instances=[{}])
        self.instance_cache_file = "{0}/{1}".format(self.init_config.get('cache_dir'),
                                                    'lxd_instances.json')
        self.metric_cache_file = "{0}/{1}".format(self.init_config.get('cache_dir'),
                                                  'lxd_metrics.json')
        self.use_bits = self.init_config.get('network_use_bits')

        self._collect_intervals = {}
        self._host_aggregate = None

        self._set_collection_intervals('disk', 'disk_collection_period')
        self._set_collection_intervals('vnic', 'vnic_collection_period')

        pool_size = self.init_config.get('max_ping_concurrency', 8)
        self.pool = Pool(pool_size)

    def _set_collection_intervals(self, interval_name, config_name):
        self._collect_intervals[interval_name] = {
            'period': int(self.init_config.get(config_name, 0)),
            'last_collect': datetime.fromordinal(1),
            'skip': False}

    def _test_vm_probation(self, created):
        """Test to see if a VM was created within the probation period.

        Convert an ISO-8601 timestamp into UNIX epoch timestamp from now
        and compare that against configured vm_probation.  Return the
        number of seconds this VM will remain in probation.
        """
        dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%SZ')
        created_sec = (time.time() - timegm(dt.timetuple()))
        probation_time = self.init_config.get('vm_probation', 300) - created_sec
        return int(probation_time)

    def _get_metric_name(self, orig_name):
        # Rename "tx" to "out" and "rx" to "in"
        metric_name = orig_name.replace("tx", "out").replace("rx", "in")
        if self.use_bits:
            metric_name = metric_name.replace("bytes", "bits")
        return metric_name

    @staticmethod
    def _get_metric_rate_name(metric_name):
        """Change the metric name to a rate, i.e. "net.rx_bytes"
        gets converted to "net.rx_bytes_sec"
        """
        return "{0}_sec".format(metric_name)

    def _update_instance_cache(self):
        """Collect instance_id, project_id, and AZ for all instance UUIDs
        """

        id_cache = {}
        flavor_cache = {}
        # Get a list of all instances from the Nova API
        session = keystone.get_session(**self.init_config)
        nova_client = n_client.Client(
            "2.1", session=session,
            endpoint_type=self.init_config.get("endpoint_type", "publicURL"),
            service_type="compute",
            region_name=self.init_config.get('region_name'),
            client_name='monasca-agent[libvirt]',
            client_version=ma_version.version_string)
        self._get_this_host_aggregate(nova_client)
        instances = nova_client.servers.list(
            search_opts={'all_tenants': 1, 'host': self.hostname})

        #
        # Only make the keystone call to get the tenant list
        # if we are configured to publish tenant names.
        #
        tenants = []
        if self.init_config.get('metadata') and 'tenant_name' in self.init_config.get('metadata'):
            tenants = utils.get_tenant_list(self.init_config, self.log)

        for instance in instances:
            instance_ports = []
            inst_name = instance.__getattr__('OS-EXT-SRV-ATTR:instance_name')
            inst_az = instance.__getattr__('OS-EXT-AZ:availability_zone')
            if instance.flavor['id'] in flavor_cache:
                inst_flavor = flavor_cache[instance.flavor['id']]
            else:
                try:
                    inst_flavor = nova_client.flavors.get(instance.flavor['id'])
                except NotFound as e:
                    self.log.error('Skipping VM {}: {}'.format(inst_name, e))
                    continue
                flavor_cache[instance.flavor['id']] = inst_flavor

            id_cache[inst_name] = {'instance_uuid': instance.id,
                                   'hostname': instance.name,
                                   'zone': inst_az,
                                   'created': instance.created,
                                   'tenant_id': instance.tenant_id,
                                   'vcpus': inst_flavor.vcpus,
                                   'ram': inst_flavor.ram,
                                   'disk': inst_flavor.disk,
                                   'instance_ports': instance_ports}

            tenant_name = utils.get_tenant_name(tenants, instance.tenant_id)
            if tenant_name:
                id_cache[inst_name]['tenant_name'] = tenant_name

            for config_var in ['metadata', 'customer_metadata']:
                if self.init_config.get(config_var):
                    for metadata in self.init_config.get(config_var):
                        if instance.metadata.get(metadata):
                            id_cache[inst_name][metadata] = (instance.metadata.
                                                             get(metadata))

        id_cache['last_update'] = int(time.time())

        # Write the updated cache
        try:
            with open(self.instance_cache_file, 'w') as cache_json:
                json.dump(id_cache, cache_json)
            if stat.S_IMODE(os.stat(self.instance_cache_file).st_mode) != 0o600:
                os.chmod(self.instance_cache_file, 0o600)
        except IOError as e:
            self.log.error("Cannot write to {0}: {1}".format(self.instance_cache_file, e))

        return id_cache

    def _load_instance_cache(self):
        """Load the cache map of instance names to Nova data.
           If the cache does not yet exist or is damaged, (re-)build it.
        """
        instance_cache = {}
        try:
            with open(self.instance_cache_file, 'r') as cache_json:
                instance_cache = json.load(cache_json)

                # Is it time to force a refresh of this data?
                if self.init_config.get('nova_refresh') is not None:
                    time_diff = time.time() - instance_cache['last_update']
                    if time_diff > self.init_config.get('nova_refresh'):
                        self._update_instance_cache()
        except (IOError, TypeError, ValueError):
            # The file may not exist yet, or is corrupt.  Rebuild it now.
            self.log.warning("Instance cache missing or corrupt, rebuilding.")
            instance_cache = self._update_instance_cache()
            pass

        return instance_cache

    def _load_metric_cache(self):
        """Load the counter metrics from the previous collection iteration
        """
        metric_cache = {}
        try:
            with open(self.metric_cache_file, 'r') as cache_json:
                metric_cache = json.load(cache_json)
        except (IOError, TypeError, ValueError):
            # The file may not exist yet.
            self.log.warning("Metrics cache missing or corrupt, rebuilding.")
            metric_cache = {}
            pass

        return metric_cache

    def _update_metric_cache(self, metric_cache, run_time):
        # Remove inactive VMs from the metric cache
        write_metric_cache = deepcopy(metric_cache)
        for instance in metric_cache:
            if (('mem.free_mb' not in metric_cache[instance] or
                 self._test_vm_probation(time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                         time.gmtime(metric_cache[instance]['mem.free_mb']['timestamp'] + run_time))) < 0)):
                self.log.info("Expiring old/empty {0} from cache".format(instance))
                del(write_metric_cache[instance])
        try:
            with open(self.metric_cache_file, 'w') as cache_json:
                json.dump(write_metric_cache, cache_json)
            if stat.S_IMODE(os.stat(self.metric_cache_file).st_mode) != 0o600:
                os.chmod(self.metric_cache_file, 0o600)
        except IOError as e:
            self.log.error("Cannot write to {0}: {1}".format(self.metric_cache_file, e))

    def _inspect_network(self, insp, inst, inst_name, instance_cache, metric_cache, dims_customer, dims_operations):
        """Inspect network metrics for an instance"""
        for vnic in insp.inspect_vnics(inst):
            sample_time = time.time()
            vnic_dimensions = {'device': vnic[0].name}
            for metric in vnic[1]._fields:
                metric_name = "net.{0}".format(metric)
                if metric_name not in metric_cache[inst_name]:
                    metric_cache[inst_name][metric_name] = {}

                value = int(vnic[1].__getattribute__(metric))
                if vnic[0].name in metric_cache[inst_name][metric_name]:
                    last_update_time = metric_cache[inst_name][metric_name][vnic[0].name]['timestamp']
                    time_diff = sample_time - float(last_update_time)
                    rate_value = self._calculate_rate(value,
                                                      metric_cache[inst_name][metric_name][vnic[0].name]['value'],
                                                      time_diff)
                    if rate_value < 0:
                        # Bad value, save current reading and skip
                        self.log.warn("Ignoring negative network sample for: "
                                      "{0} new value: {1} old value: {2}"
                                      .format(inst_name, value,
                                              metric_cache[inst_name][metric_name][vnic[0].name]['value']))
                        metric_cache[inst_name][metric_name][vnic[0].name] = {
                            'timestamp': sample_time,
                            'value': value}
                        continue
                    rate_name = self._get_metric_rate_name(metric_name)
                    rate_name = self._get_metric_name(rate_name)
                    if self.use_bits:
                        rate_value *= 8
                    # Customer
                    this_dimensions = vnic_dimensions.copy()
                    this_dimensions.update(dims_customer)
                    self.gauge(rate_name, rate_value,
                               dimensions=this_dimensions,
                               delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                               hostname=instance_cache.get(inst_name)['hostname'])
                    # Operations (metric name prefixed with "lxd."
                    this_dimensions = vnic_dimensions.copy()
                    this_dimensions.update(dims_operations)
                    self.gauge("lxd.{0}".format(rate_name), rate_value,
                               dimensions=this_dimensions)
                # Report raw counters.
                mapped_name = self._get_metric_name(metric_name)
                weighted_value = value
                if self.use_bits:
                    weighted_value = value * 8
                # Customer
                this_dimensions = vnic_dimensions.copy()
                this_dimensions.update(dims_customer)
                self.gauge(mapped_name, weighted_value,
                           dimensions=this_dimensions,
                           delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                           hostname=instance_cache.get(inst_name)['hostname'])
                # Operations (metric name prefixed with "lxd.")
                this_dimensions = vnic_dimensions.copy()
                this_dimensions.update(dims_operations)
                self.gauge("lxd.{0}".format(mapped_name),
                           weighted_value, dimensions=this_dimensions)
                # Save this metric to the cache
                metric_cache[inst_name][metric_name][vnic[0].name] = {
                    'timestamp': sample_time,
                    'value': value}

    def _inspect_cpu(self, insp, inst, inst_name, instance_cache, metric_cache, dims_customer, dims_operations):
        """Inspect cpu metrics for an instance"""

        sample_time = float("{:9f}".format(time.time()))
        cpu_info = insp.inspect_cpus(inst)

        if 'cpu.time' in metric_cache[inst_name] and cpu_info.number:
            # I have a prior value, so calculate the used_cores & push the metric
            cpu_diff = cpu_info.time - metric_cache[inst_name]['cpu.time']['value']
            time_diff = sample_time - float(metric_cache[inst_name]['cpu.time']['timestamp'])
            # Convert time_diff to nanoseconds, and calculate percentage
            used_cores = (cpu_diff / (time_diff * 1000000000))
            # Divide by the number of cores to normalize the percentage
            normalized_perc = (used_cores / cpu_info.number) * 100
            if used_cores < 0:
                # Bad value, save current reading and skip
                self.log.warn("Ignoring negative CPU sample for: "
                              "{0} new cpu time: {1} old cpu time: {2}"
                              .format(inst_name, cpu_info.time,
                                      metric_cache[inst_name]['cpu.time']['value']))
                metric_cache[inst_name]['cpu.time'] = {'timestamp': sample_time,
                                                       'value': cpu_info.time}
                return

            self.gauge('cpu.total_cores', float(cpu_info.number),
                       dimensions=dims_customer,
                       delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                       hostname=instance_cache.get(inst_name)['hostname'])
            self.gauge('cpu.used_cores', float(used_cores),
                       dimensions=dims_customer,
                       delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                       hostname=instance_cache.get(inst_name)['hostname'])
            self.gauge('cpu.utilization_perc', int(round(used_cores * 100, 0)),
                       dimensions=dims_customer,
                       delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                       hostname=instance_cache.get(inst_name)['hostname'])
            self.gauge('cpu.utilization_norm_perc', int(round(normalized_perc, 0)),
                       dimensions=dims_customer,
                       delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                       hostname=instance_cache.get(inst_name)['hostname'])

            self.gauge('lxd.cpu.total_cores', float(cpu_info.number),
                       dimensions=dims_operations)
            self.gauge('lxd.cpu.used_cores', float(used_cores),
                       dimensions=dims_operations)
            self.gauge('lxd.cpu.utilization_perc', int(round(used_cores * 100, 0)),
                       dimensions=dims_operations)
            self.gauge('lxd.cpu.utilization_norm_perc', int(round(normalized_perc, 0)),
                       dimensions=dims_operations)

            cpu_time_name = 'cpu.time_ns'
            # cpu.time_ns for owning tenant
            self.gauge(cpu_time_name, cpu_info.time,
                       dimensions=dims_customer,
                       delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                       hostname=instance_cache.get(inst_name)['hostname'])
            # lxd.cpu.time_ns for operations tenant
            self.gauge("lxd.{0}".format(cpu_time_name), cpu_info.time,
                       dimensions=dims_operations)
        metric_cache[inst_name]['cpu.time'] = {'timestamp': sample_time,
                                               'value': cpu_info.time}

    def _inspect_state(self, insp, inst, inst_name, instance_cache, dims_customer, dims_operations):
        """Look at the state of the instance, publish a metric using a
           user-friendly description in the 'detail' metadata, and return
           a status code (calibrated to UNIX status codes where 0 is OK)
           so that remaining metrics can be skipped if the VM is not OK
        """
        VM_STATES = dict({
            self.OperationCreated: "Operation created",
            self.Started: "Started",
            self.Stopped: "Stopped",
            self.Running: "Running",
            self.Cancelling: "Cancelling",
            self.Pending: "Pending",
            self.Success: "Success",
            self.Failure: "Failure",
            self.Cancelled: "Cancelled",
            self.Starting: "Starting",
            self.Stopping: "Stopping",
            self.Aborting: "Aborting",
            self.Freezing: "Freezing",
            self.Frozen: "Frozen",
            self.Thawed: "Thawed",
            self.Error: "Error",
        })

        DOM_STATES = dict({
            self.Running: 'VM is running',
            self.Stopped: 'VM is shutted down',
            self.Frozen: 'VM is frozen',
        })
        dom_status = inst.status_code
        metatag = None

        details = ''
        if dom_status in DOM_STATES:
            details = DOM_STATES[dom_status]
        elif dom_status in VM_STATES:
            details = VM_STATES[dom_status]

        metatag = {'detail': details}
        # normalize host_alive status, Running -> zero - monasca expect zero as 'good' state
        self.gauge('host_alive_status',
                   0 if dom_status == self.Running else dom_status,
                   dimensions=dims_customer,
                   delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                   hostname=instance_cache.get(inst_name)['hostname'],
                   value_meta=metatag)
        self.gauge('lxd.host_alive_status', 0 if dom_status == self.Running else dom_status,
                   dimensions=dims_operations,
                   value_meta=metatag)

    def prepare_run(self):
        """Check if it is time for measurements to be collected"""
        for name, collection in self._collect_intervals.items():
            if collection['period'] <= 0:
                continue

            time_since_last = datetime.now() - collection['last_collect']
            # Handle times that are really close to the collection period
            period_with_fudge_factor = timedelta(0, collection['period'] - 1,
                                                 500000)

            if time_since_last < period_with_fudge_factor:
                self.log.debug('Skipping {} collection for {} seconds'.format(
                               name,
                               (collection['period'] - time_since_last.seconds)))
                collection['skip'] = True
            else:
                collection['skip'] = False
                collection['last_collect'] = datetime.now()

    # LXD API
    def _get_containers(self, lxd_client):
        """Gets the list of running containers in LXD."""
        return lxd_client.containers.all()

    def check(self, instance):
        """Gather VM metrics for each instance"""

        time_start = time.time()

        # Load metric cache
        metric_cache = self._load_metric_cache()

        # Load the nova-obtained instance data cache
        instance_cache = self._load_instance_cache()

        # Build dimensions for both the customer and for operations
        dims_base = self._set_dimensions({'service': 'compute', 'component': 'lxd'}, instance)

        # Define aggregate gauges, gauge name to metric name
        agg_gauges = {'vcpus': 'nova.lxd.cpu.total_allocated',
                      'ram': 'nova.lxd.mem.total_allocated_mb',
                      'disk': 'nova.lxd.disk.total_allocated_gb'}
        agg_values = {}
        for gauge in agg_gauges.keys():
            agg_values[gauge] = 0

        insp = LXDInspector()
        updated_cache_this_time = False

        lxd_client = pylxd.Client()
        for inst in self._get_containers(lxd_client):
            # Verify that this instance exists in the cache.  Add if necessary.
            inst_name = inst.name
            if inst_name not in instance_cache and not updated_cache_this_time:
                #
                # If we have multiple ghost VMs, we'll needlessly
                # update the instance cache.  Let's limit the cache
                # update to once per agent wakeup.
                #
                updated_cache_this_time = True
                instance_cache = self._update_instance_cache()

            # Build customer dimensions
            try:
                dims_customer = dims_base.copy()
                dims_customer['resource_id'] = instance_cache.get(inst_name)['instance_uuid']
                dims_customer['zone'] = instance_cache.get(inst_name)['zone']
                # Add dimensions that would be helpful for operations
                dims_operations = dims_customer.copy()
                dims_operations['tenant_id'] = instance_cache.get(inst_name)['tenant_id']
                dims_operations = self._update_dims_with_metadata(instance_cache, inst_name, dims_operations)
                if self.init_config.get('customer_metadata'):
                    for metadata in self.init_config.get('customer_metadata'):
                        metadata_value = (instance_cache.get(inst_name).
                                          get(metadata))
                        if metadata_value:
                            dims_customer[metadata] = metadata_value
                # Remove customer 'hostname' dimension, this will be replaced by the VM name
                del(dims_customer['hostname'])
                #
                # Add this hypervisor's host aggregate as a dimension if
                # configured to do so and we had a match on the regex for
                # this host.
                #
                if self._host_aggregate:
                    dims_operations['host_aggregate'] = self._host_aggregate
            except TypeError:
                # Nova can potentially get into a state where it can't see an
                # instance, but libvirt can.  This would cause TypeErrors as
                # incomplete data is cached for this instance.  Log and skip.
                self.log.error("{0} is not known to nova after instance cache update -- skipping this ghost VM.".format(inst_name))
                continue

            # Accumulate aggregate data
            for gauge in agg_gauges:
                if gauge in instance_cache.get(inst_name):
                    agg_values[gauge] += instance_cache.get(inst_name)[gauge]

            # Skip instances created within the probation period
            vm_probation_remaining = self._test_vm_probation(instance_cache.get(inst_name)['created'])
            if (vm_probation_remaining >= 0):
                self.log.info("Libvirt: {0} in probation for another {1} seconds".format(instance_cache.get(inst_name)['hostname'].encode('utf8'),
                                                                                         vm_probation_remaining))
                continue

            # Skip further processing on VMs that are not in an active state
            self._inspect_state(insp, inst, inst_name, instance_cache,
                                dims_customer, dims_operations)
            if inst.status_code != self.Running:
                continue

            # Skip the remainder of the checks if alive_only is True in the config
            if self.init_config.get('alive_only'):
                continue

            if inst_name not in metric_cache:
                metric_cache[inst_name] = {}

            if self.init_config.get('vm_cpu_check_enable'):
                self._inspect_cpu(insp, inst, inst_name, instance_cache, metric_cache, dims_customer, dims_operations)

            if not self._collect_intervals['vnic']['skip']:
                if self.init_config.get('vm_network_check_enable'):
                    self._inspect_network(insp, inst, inst_name, instance_cache, metric_cache, dims_customer, dims_operations)

            mem_stats = insp.memoryStats(inst)
            mem_metrics = {'mem.free_mb': float(mem_stats['unused']) / 1024,
                           'mem.swap_used_mb': float(mem_stats['swap_out']) / 1024,
                           'mem.total_mb': float(mem_stats['available']) / 1024,
                           'mem.used_mb': float(mem_stats['available'] - mem_stats['unused']) / 1024,
                           'mem.free_perc': float(mem_stats['unused']) / float(mem_stats['available']) * 100}
            sample_time = float("{:9f}".format(time.time()))
            metric_cache[inst_name]['mem.free_mb'] = {
                'timestamp': sample_time,
                'value': mem_metrics['mem.total_mb']}
            for name in mem_metrics:
                self.gauge(name, mem_metrics[name], dimensions=dims_customer,
                           delegated_tenant=instance_cache.get(inst_name)['tenant_id'],
                           hostname=instance_cache.get(inst_name)['hostname'])
                self.gauge("lxd.{0}".format(name), mem_metrics[name],
                           dimensions=dims_operations)

        # Save these metrics for the next collector invocation
        self._update_metric_cache(metric_cache, math.ceil(time.time() - time_start))

        # Publish aggregate metrics
        for gauge in agg_gauges:
            self.gauge(agg_gauges[gauge], agg_values[gauge], dimensions=dims_base)

    def _calculate_rate(self, current_value, cache_value, time_diff):
        """Calculate rate based on current, cache value and time_diff."""
        try:
            rate_value = (current_value - cache_value) / time_diff
        except ZeroDivisionError as e:
            self.log.error("Time difference between current time and "
                           "last_update time is 0 . {0}".format(e))
            #
            # Being extra safe here, in case we divide by zero
            # just skip this reading with check below.
            #
            rate_value = -1
        return rate_value

    def _update_dims_with_metadata(self, instance_cache, inst_name, dim_operations):
        """Update operations dimensions with metadata."""
        dims = dim_operations
        if self.init_config.get('metadata'):
            for metadata in self.init_config.get('metadata'):
                if 'vm_name' == metadata:
                    metadata_value = (instance_cache.get(inst_name).
                                      get('hostname'))
                else:
                    metadata_value = (instance_cache.get(inst_name).
                                      get(metadata))
                if metadata_value:
                    dims[metadata] = metadata_value
        return dims

    def _get_this_host_aggregate(self, nova_client):
        """Determine the host aggregate for this hypervisor."""
        host_agg_cfg_re = self.init_config.get('host_aggregate_re', None)
        if not host_agg_cfg_re:
            return

        try:
            agg_re = re.compile(host_agg_cfg_re)
            aggs = nova_client.aggregates.list()
            for idx, agg in enumerate(aggs):
                if re.match(agg_re, aggs[idx].name) and self.hostname in aggs[idx].hosts:
                    self._host_aggregate = str(aggs[idx].name)
                    #
                    # Not expecting multiple matches, if we've got a match we're done.
                    #
                    break

        except Exception as e:
            msg = "Failed to list host aggregates, won't publish aggregate dimension: '{0}'"
            self.log.error(msg.format(e))
