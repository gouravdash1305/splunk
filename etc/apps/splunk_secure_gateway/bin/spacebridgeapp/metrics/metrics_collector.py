"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.
"""

from abc import ABCMeta, abstractmethod
import json
from spacebridgeapp.util.constants import REGISTERED_DEVICES_DEVICE_ID, APPLICATION_TYPES_COLLECTION_NAME, NOBODY, \
    MOBILE_ALERTS_COLLECTION_NAME
from spacebridgeapp.metrics import telemetry_client
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject
from spacebridgeapp.rest.devices.users_devices import get_devices_for_registered_users
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader


class SpacebridgeaAppMetricsCollector(object):

    def __init__(self, logger, session_token):
        self.logger = logger
        self.metrics = [NumRegisteredDevicesMetric(session_token, logger),
                        EnabledAppsMetric(session_token, logger),
                        NumDevicesPerAppMetric(session_token, logger),
                        NumAlertsMetric(session_token, logger)]

    def run(self):
        for metric in self.metrics:
            metric.send_to_telemetry()


class SpacebridgeAppMetric():
    """
    Base class for calculating metrics.
    """

    __metaclass__ = ABCMeta

    def __init__(self, session_token, logger):
        self.session_token = session_token
        self.auth_header = SplunkAuthHeader(session_token)
        self.logger = logger

    @abstractmethod
    def calculate(self):
        """
        must return a dictionary
        """
        pass

    def send_to_telemetry(self):
        metric = self.calculate()
        telemetry_client.post_event(metric, self.auth_header, self.logger)


class NumRegisteredDevicesMetric(SpacebridgeAppMetric):
    """
    Track number of total registered devices
    """
    METRIC_NAME = "num_registered_devices"

    def calculate(self):
        devices = get_devices_for_registered_users(self.session_token)
        unique_device_ids = set()
        for device in devices:
            unique_device_ids.add(device[REGISTERED_DEVICES_DEVICE_ID])

        metric = {self.METRIC_NAME: len(unique_device_ids)}
        return metric


class NumDevicesPerAppMetric(SpacebridgeAppMetric):
    """
    Track number of registered devices broken down by app
    """
    METRIC_NAME = "num_registered_devices_per_app"

    def calculate(self):
        devices = get_devices_for_registered_users(self.session_token)
        unique_devices_per_app = {}

        for device in devices:
            app_name = device["device_type"]
            device_id = device[REGISTERED_DEVICES_DEVICE_ID]

            if app_name in unique_devices_per_app:
                device_ids = unique_devices_per_app[app_name]
                device_ids.add(device_id)
                unique_devices_per_app[app_name] = device_ids
            else:
                unique_devices_per_app[app_name] = {device_id}

        metrics = {app_name: len(unique_devices_per_app[app_name]) for app_name in unique_devices_per_app.keys()}
        return {self.METRIC_NAME : metrics}


class EnabledAppsMetric(SpacebridgeAppMetric):
    """
    Track which mobile apps are enabled in the splapp
    """
    METRIC_NAME = "enabled_mobile_apps_metrics"

    def calculate(self):
        kvstore_client = KVStoreCollectionAccessObject(APPLICATION_TYPES_COLLECTION_NAME,
                                                       self.session_token,
                                                       owner=NOBODY)
        r, app_states = kvstore_client.get_all_items()
        metrics = {}

        for app_state in json.loads(app_states):
            metrics[app_state["application_name"]] = app_state["application_enabled"]

        return {self.METRIC_NAME: metrics}


class NumAlertsMetric(SpacebridgeAppMetric):
    """
    Track how many alerts are being stored in KV Store
    """

    METRIC_NAME = "num_alerts_in_kvstore"

    def calculate(self):
        kvstore_client = KVStoreCollectionAccessObject(MOBILE_ALERTS_COLLECTION_NAME,
                                                       self.session_token,
                                                       owner=NOBODY)

        r, jsn = kvstore_client.get_collection_keys()
        collection_keys = json.loads(jsn)
        collection_size = len(collection_keys)
        return {self.METRIC_NAME: collection_size}



