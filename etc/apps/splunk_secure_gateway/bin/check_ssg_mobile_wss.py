#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved."""
# Splunk specific dependencies
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from spacebridgeapp.util import py23

import asyncio
import certifi
import ssl
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
from spacebridgeapp.util.config import secure_gateway_config as config
from autobahn.asyncio.websocket import WebSocketClientFactory, WebSocketClientProtocol

# Command specific dependencies
import uuid


class EchoState(object):
    def __init__(self):
        self.payload = str(uuid.uuid4()).encode('utf-8')
        self.ok = False
        self.message = ''


class CheckMobileWssProtocol(WebSocketClientProtocol):
    def onConnect(self, request):
        self.sendMessage(self.factory.state.payload, isBinary=True)

    def onMessage(self, payload, isBinary):
        expected = self.factory.state.payload
        match = (payload == expected)
        self.factory.state.ok = match
        if not match:
            self.factory.state.message = 'Received unknown message'

        asyncio.get_event_loop().stop()


@Configuration(type='reporting')
class SecureGatewayHttpsCheck(GeneratingCommand):
    """
    This command checks spacebridge reachability by using twisted to connect to the websocket echo endpoint and sending
    a message.  The test is considered a success if it gets back the message it sent within 10 seconds.
    By default it will inherit Splunk's proxy settings and use them.  In the command you can disable the proxy by
    passing useProxy=False.
    """
    useProxy = Option(require=False, validate=validators.Boolean(), default=True)

    def __init__(self):
        super(SecureGatewayHttpsCheck, self).__init__()
        self.echo_state = EchoState()

    def timeout(self):
        self.echo_state.message = 'Timeout'
        self.timeout_id.cancel()
        asyncio.get_event_loop().stop()

    def test_wss(self, loop):
        ws_url = "wss://{}/echo".format(config.get_spacebridge_server())

        headers = {'Authorization': "f00d"}

        use_proxy = self.useProxy

        proxy, auth = config.get_ws_https_proxy_settings()

        if use_proxy:
            # Proxy setup
            if auth:
                headers['Proxy-Authorization'] = 'Basic ' + auth
        else:
            proxy = None

        factory = WebSocketClientFactory(ws_url, headers=headers)
        factory.protocol = CheckMobileWssProtocol
        factory.state = self.echo_state
        factory.loop = loop

        context = ssl.create_default_context(cafile=certifi.where())
        coro = loop.create_connection(factory,config.get_spacebridge_server(), 443, ssl=context)

        self.timeout_id = loop.call_later(10, self.timeout)

        try:
            loop.run_until_complete(coro)
            loop.run_forever()
        except asyncio.TimeoutError:
            self.echo_state.message = 'Timeout'
        except Exception as e:
            self.echo_state.message = str(e)

        record = {'websocket': self.echo_state.ok, 'message': self.echo_state.message}

        return record

    def generate(self):
        loop = asyncio.get_event_loop()
        record = self.test_wss(loop)
        loop.close()

        yield record


dispatch(SecureGatewayHttpsCheck, sys.argv, sys.stdin, sys.stdout, __name__)
