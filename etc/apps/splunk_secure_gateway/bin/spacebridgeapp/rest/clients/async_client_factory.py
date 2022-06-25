"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

Factory class to return async client types
"""
from spacebridgeapp.rest.clients.async_client import AsyncClient
from spacebridgeapp.rest.clients.async_non_ssl_client import AsyncNonSslClient
from spacebridgeapp.rest.clients.async_kvstore_client import AsyncKvStoreClient
from spacebridgeapp.rest.clients.async_splunk_client import AsyncSplunkClient
from spacebridgeapp.rest.clients.async_spacebridge_client import AsyncSpacebridgeClient
from spacebridgeapp.metrics.telemetry_client import AsyncTelemetryClient

# Value factory selectors
from spacebridgeapp.subscriptions.subscription_client import SubscriptionClient

FACTORY = 'async_client_factory'
NON_SSL = 'async_non_ssl_client'
KVSTORE = 'async_kvstore_client'
SPLUNK = 'async_splunk_client'
SPACEBRIDGE = 'async_spacebridge_client'
TELEMETRY = 'async_telemetry_client'
SUBSCRIPTIONS = 'async_subscription_client'


class AsyncClientFactory(object):

    def __init__(self, uri,
                 spacebridge_client=None):
        """

        :param uri: string representing uri to make request to
        """
        self.uri = uri
        self._async_client = None
        self._async_non_ssl_client = None
        self._async_kvstore_client = None
        self._async_splunk_client = None
        self._async_spacebridge_client = None
        self._async_telemetry_client = None
        self._subscription_client = None
        self._spacebridge_client = spacebridge_client

    def from_value(self, value):
        """
        Helper method to get async_client by value name
        :param value:
        :return:
        """
        if FACTORY == value:
            return self
        elif NON_SSL == value:
            return self.non_ssl_client()
        elif KVSTORE == value:
            return self.kvstore_client()
        elif SPLUNK == value:
            return self.splunk_client()
        elif SPACEBRIDGE == value:
            return self.spacebridge_client()
        elif TELEMETRY == value:
            return self.telemetry_client()
        elif SUBSCRIPTIONS == value:
            return self.subscription_client()
        return None

    def async_client(self) -> AsyncClient:
        if not self._async_client:
            self._async_client = AsyncClient()

        return self._async_client

    def non_ssl_client(self) -> AsyncNonSslClient:
        if not self._async_non_ssl_client:
            self._async_non_ssl_client = AsyncNonSslClient()
        return self._async_non_ssl_client

    def kvstore_client(self) -> AsyncKvStoreClient:
        if not self._async_kvstore_client:
            self._async_kvstore_client = AsyncKvStoreClient()
        return self._async_kvstore_client

    def splunk_client(self) -> AsyncSplunkClient:
        if not self._async_splunk_client:
            self._async_splunk_client = AsyncSplunkClient(self.uri)
        return self._async_splunk_client

    def spacebridge_client(self) -> AsyncSpacebridgeClient:
        if not self._spacebridge_client:
            self._spacebridge_client = AsyncSpacebridgeClient()
        return self._spacebridge_client

    def telemetry_client(self) -> AsyncTelemetryClient:
        if not self._async_telemetry_client:
            self._async_telemetry_client = AsyncTelemetryClient()
        return self._async_telemetry_client

    def subscription_client(self) -> SubscriptionClient:
        if not self._subscription_client:
            self._subscription_client = SubscriptionClient(self.kvstore_client(), self.splunk_client())
        return self._subscription_client
