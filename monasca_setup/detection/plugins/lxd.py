# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
# Copyright 2017 Fujitsu LIMITED
# Copyright 2017 SUSE Linux GmbH

import logging
import os
import pwd
from shutil import copy
import subprocess
import sys

from oslo_config import cfg
from oslo_utils import importutils

from monasca_agent.common.psutil_wrapper import psutil
from monasca_setup import agent_config
from monasca_setup.detection import plugin
from monasca_setup.detection import utils


log = logging.getLogger(__name__)

# Directory to use for instance and metric caches (preferred tmpfs "/dev/shm")
cache_dir = "/dev/shm"
# Maximum age of instance cache before automatic refresh (in seconds)
nova_refresh = 60 * 60 * 4  # Four hours
# Probation period before metrics are gathered for a VM (in seconds)
vm_probation = 60 * 5  # Five minutes
# List of instance metadata keys to be sent as dimensions
# By default 'scale_group' metadata is used here for supporting auto
# scaling in Heat.
metadata = ['scale_group', 'vm_name']
# Include scale group dimension for customer metrics.
customer_metadata = ['scale_group']
# VNIC metrics can be collected at a larger interval than other vm metrics
default_vnic_collection_period = 0

# Arguments which should be written as integers, not strings
INT_ARGS = ['vnic_collection_period', 'nova_refresh', 'vm_probation']

_REQUIRED_OPTS = [
    {'opt': cfg.StrOpt('username'), 'group': 'keystone_authtoken'},
    {'opt': cfg.StrOpt('password'), 'group': 'keystone_authtoken'},
    {'opt': cfg.StrOpt('project_name'), 'group': 'keystone_authtoken'},
    {'opt': cfg.StrOpt('auth_url'), 'group': 'keystone_authtoken'},
]
"""Nova configuration opts required by this plugin"""


class LXD(plugin.Plugin):
    """Configures VM monitoring through Nova"""

    FAILED_DETECTION_MSG = 'lxd plugin will not not be configured.'

    def _detect(self):
        """Set self.available True if the process and config file are detected
        """

        # NOTE(trebskit) bind each check we execute to another one
        # that way if X-one fails following won't be executed
        # and detection phase will end faster
        nova_proc = utils.find_process_name('nova-compute')
        has_deps = self.dependencies_installed() if nova_proc else None
        nova_conf = self._find_nova_conf(nova_proc) if has_deps else None
        has_cache_dir = self._has_cache_dir() if nova_conf else None
        agent_user = utils.get_agent_username() if has_cache_dir else None

        self.available = nova_conf and has_cache_dir and self._check_lxd_driver()
        if not self.available:
            if not nova_proc:
                detailed_message = '\tnova-compute process not found.'
                log.info('%s\n%s' % (detailed_message,
                                     self.FAILED_DETECTION_MSG))
            elif not has_deps:
                detailed_message = ('\tRequired dependencies were not found.\n'
                                    'Run pip install monasca-agent[libvirt] '
                                    'to install all dependencies.')
                log.warning('%s\n%s' % (detailed_message,
                                        self.FAILED_DETECTION_MSG))
            elif not has_cache_dir:
                detailed_message = '\tCache directory %s not found' % cache_dir
                log.warning('%s\n%s' % (detailed_message,
                                        self.FAILED_DETECTION_MSG))
            elif not nova_conf:
                detailed_message = ('\tnova-compute process was found, '
                                    'but it was impossible to '
                                    'read it\'s configuration.')
                log.warning('%s\n%s' % (detailed_message,
                                        self.FAILED_DETECTION_MSG))
        else:
            self.nova_conf = nova_conf
            self._agent_user = agent_user

    def build_config(self):
        """Build the config as a Plugins object and return back.
        """
        config = agent_config.Plugins()
        init_config = self._get_init_config()

        # Handle monasca-setup detection arguments, which take precedence
        if self.args:
            for arg in self.args:
                if arg in INT_ARGS:
                    value = self.args[arg]
                    try:
                        init_config[arg] = int(value)
                    except ValueError:
                        log.warn("\tInvalid integer value '{0}' for parameter {1}, ignoring value"
                                 .format(value, arg))
                else:
                    init_config[arg] = self.literal_eval(self.args[arg])

        config['lxd'] = {'init_config': init_config, 'instances': []}
        return config

    def dependencies_installed(self):
        return importutils.try_import('novaclient.client', False) and \
            importutils.try_import('pylxd', False)

    def _get_init_config(self):
        keystone_auth_section = self.nova_conf['keystone_authtoken']
        init_config = {
            'cache_dir': cache_dir,
            'nova_refresh': nova_refresh,
            'metadata': metadata,
            'vm_probation': vm_probation,
            'customer_metadata': customer_metadata,
            'vnic_collection_period': default_vnic_collection_period,
            'vm_cpu_check_enable': True,
            'vm_network_check_enable': True,
            'username': keystone_auth_section['username'],
            'password': keystone_auth_section['password'],
            'project_name': keystone_auth_section['project_name'],
            'auth_url': keystone_auth_section['auth_url']
        }
        return init_config

    @staticmethod
    def _has_cache_dir():
        return os.path.isdir(cache_dir)

    @staticmethod
    def _find_nova_conf(nova_process):
        try:
            nova_cmd = nova_process.as_dict(['cmdline'])['cmdline']
            return utils.load_oslo_configuration(from_cmd=[arg for arg in nova_cmd if "log-file" not in arg],
                                                 in_project='nova',
                                                 for_opts=_REQUIRED_OPTS)
        except cfg.Error:
            log.exception('Failed to load nova configuration')
        return None

    @staticmethod
    def _check_lxd_driver():
        opt_group = cfg.OptGroup(name='DEFAULT', title='Default group')
        conf = cfg.ConfigOpts()
        conf.register_opt(cfg.StrOpt('compute_driver', default='', help=('Hypervisor driver')),
                          group=opt_group)

        LXD_DRIVER = 'lxd.LXDDriver'
        try:
            conf(['--config-file', '/etc/nova/nova-compute.conf'])
            return conf.DEFAULT.compute_driver == LXD_DRIVER
        except cfg.Error:
            log.exception('Failed to load nova-compute configuration')
        return False
