"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

Configuration utility
"""

import os
from splunk.clilib import cli_common as cli
from splunk.clilib.bundle_paths import get_base_path
from spacebridgeapp.util import py23
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT
from spacebridgeapp.util.test_state import get_test_state


def parse_proxy_settings(proxy_url, default_port=DEFAULT_HTTP_PORT):
    """
    Helper to parse our proxy settings
    :param proxy_url:
    :param default_port:
    :return:
    """
    if proxy_url is None:
        return {}

    # Strip https:// or http://
    url = proxy_url.replace('http://', '')
    url = url.replace('https://', '').strip()

    # Split by '@', indicates basic authentication
    if '@' in url:
        auth, proxy_host_port = url.split('@')
    else:
        auth, proxy_host_port = None, url

    # Split by ':'
    if ':' in proxy_host_port:
        host, port = proxy_host_port.split(':')
    else:
        host = proxy_host_port
        port = default_port

    if auth is not None:
        auth = py23.b64encode_to_str(auth.encode('utf-8')).strip()
    else:
        auth = None

    return {'host': host, 'port': int(port), 'auth': auth}


def get_ws_proxy_settings(proxy_url, default_port=DEFAULT_HTTP_PORT):
    """
    This is a helper method to break up a proxy_url into the components required for WebSocketClientFactory proxy setup

    The WebSocketClientFactory required params in the following formats:

    proxy = {'host': 'hostname', 'port': port}
    headers['Proxy-Authentication'] = 'Basic ' + basic_authentication

    :param proxy_url:
    :param default_port:
    :return: proxy dictionary and basic_authentication, None in both cases if not available
    """
    if proxy_url is None:
        return None, None

    # Initialize return variables
    proxy = None

    # Parse proxy url
    proxy_settings = parse_proxy_settings(proxy_url, default_port)
    auth = proxy_settings['auth']
    host = proxy_settings['host']
    port = proxy_settings['port']

    if host is not None and port is not None:
        proxy = {'host': host, 'port': port}

    return proxy, auth


class SecureGatewayConfig(object):
    """
    Class to encapsulate configuration settings for secure gateway configuration.
    """

    # Setup Keys
    SETUP = 'setup'
    SPACEBRIDGE_SERVER = 'spacebridge_server'
    # The load balancer address should have the following format: <proxy>://<host>:<port>/
    LOAD_BALANCER_ADDRESS = 'load_balancer_address'
    LOG_LEVEL = 'log_level'
    CLUSTER_MONITOR_INTERVAL = 'cluster_monitor_interval'
    ASYNC_TIMEOUT = 'async_timeout'
    MTLS = 'mtls'

    # Client Config
    CLIENT = 'client'
    REQUEST_TIMEOUT_SECS = 'request_timeout_secs'

    # Websocket
    WEBSOCKET = 'websocket'
    RECONNECT_MAX_DELAY = 'reconnect_max_delay'

    # Subscription Keys
    SUBSCRIPTION = 'subscription'
    # The amount of time in seconds before ssg_subscription_modular_input is restarted
    MANAGER_LIFETIME_SECONDS = 'manager_lifetime_seconds'
    MANAGER_INTERVAL_SECONDS = 'manager_interval_seconds'

    # Dashboard Keys
    DASHBOARD = 'dashboard'
    # The maximum number of dashboards that can be requested
    DASHBOARD_LIST_MAX_COUNT = 'dashboard_list_max_count'

    # ProxyConfig
    PROXY_CONFIG = 'proxyConfig'
    HTTP_PROXY = 'http_proxy'
    HTTPS_PROXY = 'https_proxy'

    # Registration keys
    REGISTRATION = 'registration'
    REGISTRATION_WEBHOOK_URL = 'registration_webhook_url'
    WEBHOOK_VERIFY_SSL = 'webhook_verify_ssl'

    # Config defaults
    DEFAULT_SPACEBRIDGE_SERVER = "prod.spacebridge.spl.mobi"
    DEFAULT_CLUSTER_MONITOR_INTERVAL = '300'
    DEFAULT_REQUEST_TIMEOUT_SECS = '30'
    DEFAULT_ASYNC_TIMEOUT_SECS = '15'

    def __init__(self, appname, conf_filename):
        # In unit testing scenario we don't want to use btool
        if get_test_state():
            app_path = os.path.join(get_base_path(), appname)
            self.config = cli.getAppConf(conf_filename, appname, use_btool=False, app_path=app_path)
        else:
            self.config = cli.getMergedConf(conf_filename)

    def get_config_keys(self, stanza=SETUP):
        return self.config.get(stanza, {})

    def get_config(self, stanza=SETUP, key=None, default=None):
        config_keys = self.get_config_keys(stanza)
        return config_keys.get(key, default)

    def get_config_as_int(self, stanza=SETUP, key=None, default=None):
        value = self.get_config(stanza=stanza, key=key, default=default)
        return int(value) if value.isdigit() else int(default)

    def get_config_as_bool(self, stanza=SETUP, key=None, default='False'):
        value = self.get_config(stanza, key, default)
        as_bool = (value.lower() == 'true')
        return as_bool

    def get_async_timeout_secs(self, default=DEFAULT_ASYNC_TIMEOUT_SECS):
        """
        Helper to get async timeout set by in config file
        :return:
        """
        return self.get_config_as_int(
            stanza=self.SETUP, key=self.ASYNC_TIMEOUT, default=default)

    def get_request_timeout_secs(self):
        """
        Helper to get client request_timeout_secs
        :return:
        """
        return self.get_config_as_int(
            stanza=self.CLIENT, key=self.REQUEST_TIMEOUT_SECS, default=self.DEFAULT_REQUEST_TIMEOUT_SECS)

    def get_registration_webhook_url(self):
        """
        Helper get registration webhook url from config, return None if not found
        """

        return self.get_config(stanza=self.REGISTRATION, key=self.REGISTRATION_WEBHOOK_URL, default=None)

    def get_webhook_verify_ssl(self):
        """
        Helper get registration webhook url from config, return None if not found
        """

        return self.get_config_as_bool(stanza=self.REGISTRATION, key=self.WEBHOOK_VERIFY_SSL, default='true')

    def get_mtls_enabled(self):
        return self.get_config_as_bool(stanza=self.SETUP, key=self.MTLS)

    def get_cluster_monitor_interval(self):
        """
        Helper to get SETUP cluster_monitor_interval
        :return:
        """
        return self.get_config_as_int(key=self.CLUSTER_MONITOR_INTERVAL, default=self.DEFAULT_CLUSTER_MONITOR_INTERVAL)

    def get_spacebridge_server(self):
        return self.get_config(key=self.SPACEBRIDGE_SERVER, default=self.DEFAULT_SPACEBRIDGE_SERVER)

    def get_spacebridge_domain(self):
        return 'https://' + self.get_spacebridge_server()

    def get_proxy_cfg(self):
        try:
            # Initially look for proxyConfg in securegateway.conf
            proxy_cfg = self.get_config_keys(self.PROXY_CONFIG)
            # Fall back to look at severs.conf for proxyConfig
            if not proxy_cfg:
                proxy_cfg = cli.getConfStanza('server', self.PROXY_CONFIG)
            return proxy_cfg
        except:
            return None

    def get_https_proxy(self):
        try:
            proxy_cfg = self.get_proxy_cfg()
            return proxy_cfg.get(self.HTTPS_PROXY)
        except Exception:
            return None

    def get_proxies(self):
        try:
            proxies = {}
            proxy_cfg = self.get_proxy_cfg()

            # get http_proxy
            http_proxy = proxy_cfg.get(self.HTTP_PROXY)
            if http_proxy:
                proxies['http'] = http_proxy

            # get https_proxy
            https_proxy = proxy_cfg.get(self.HTTPS_PROXY)
            if https_proxy:
                proxies['https'] = https_proxy

            return proxies
        except Exception:
            return {}

    def get_ws_https_proxy_settings(self):
        """
        Helper to get https proxy settings for WebSocket config usage
        :return:
        """
        return get_ws_proxy_settings(self.get_https_proxy(), DEFAULT_HTTPS_PORT)

    def get_https_proxy_settings(self):
        """
        Helper to get https proxy settings for twisted config usage
        :return:
        """
        return parse_proxy_settings(self.get_https_proxy(), DEFAULT_HTTPS_PORT)



secure_gateway_config = SecureGatewayConfig(SPACEBRIDGE_APP_NAME, 'securegateway')
