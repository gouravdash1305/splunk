"""
Asyncio based websocket client protocol
"""
import asyncio
from autobahn.asyncio.websocket import WebSocketClientProtocol
from cloudgateway.private.util import time_utils
from cloudgateway.private.asyncio.websocket.cloudgateway_init import send_public_key_to_spacebridge


class AioSpacebridgeServerProtocol(WebSocketClientProtocol):

    """ Defines websocket protocol for talking to cloud gateway using asyncio"""

    PING_FREQUENCY_SECONDS = 60
    SPACEBRIDGE_RECONNECT_THRESHOLD_SECONDS = 60

    def __init__(self, *args, **kwargs):
        super(AioSpacebridgeServerProtocol, self).__init__(*args, **kwargs)
        self.stop_event_loop_on_close = True

    def onConnect(self, request):
        try:
            self.logger.info("Connected to . self={}, response={}".format(id(self), str(request)))
        except Exception as e:
            self.logger.exception("Exception onConnect")


    async def onOpen(self):
        """
        When websocket connection is opened, kick off monitoring tasks

        """
        self.ping_call_id = None
        self.check_spacebridge_ping_id = None
        self.last_spacebridge_ping = time_utils.get_current_timestamp()
        self.logger.info(
            "WebSocket connection open. self={}, current_time={}".format(id(self), self.last_spacebridge_ping))

        self.ping_spacebridge()
        self.check_spacebridge_pings()

        if self.parent_process_monitor:
            self.parent_process_monitor.monitor(self.logger, websocket_ctx=self.websocket_context, protocol=self)

        if self.websocket_context:
            try:
                await self.websocket_context.on_open(self)
            except Exception as e:
                self.logger.exception("Exception on websocket_ctx onopen")

    async def onMessage(self, payload, isBinary):
        """ When receiving message from spacebridge"""
        try:
            await self.message_handler.on_message(payload, self)
        except Exception as e:
            self.logger.exception("Exception onMessage={}".format(e))

    async def onClose(self, wasClean, code, reason):
        self.logger.info("WebSocket connection closed: self={}, wasClean={}, code={}, reason={}"
                         .format(id(self), wasClean, code, str(reason)))
        if hasattr(self, 'ping_call_id') and self.ping_call_id:
            self.ping_call_id.cancel()

        if hasattr(self, 'check_spacebridge_ping_id') and self.check_spacebridge_ping_id:
            self.check_spacebridge_ping_id.cancel()

        if self.websocket_context:
            try:
                await self.websocket_context.on_close(wasClean, code, reason, self)
            except Exception as e:
                self.logger.exception("Exception on websocket_ctx on_close")

        if self.stop_event_loop_on_close:
            asyncio.get_event_loop().stop()


    async def onPing(self, payload):
        """
        When receiving ping message from spacebridge
        """
        self.last_spacebridge_ping = time_utils.get_current_timestamp()
        self.logger.info("Received Ping from Spacebridge self={}, time={}".format(id(self), self.last_spacebridge_ping))
        self.sendPong()
        self.logger.info("Sent Pong")

        if self.websocket_context:
            try:
                await self.websocket_context.on_ping(payload, self)
            except Exception as e:
                self.logger.exception("Exception on websocket_ctx on_ping")

    async def onPong(self, payload):
        """ When receiving pong message from spacebridge
        """

        self.logger.info("Received Pong, self={}".format(id(self)))
        if self.websocket_context:
            try:
                await self.websocket_context.on_pong(payload, self)
            except Exception as e:
                self.logger.exception("Exception on websocket_ctx on_pong")

    def ping_spacebridge(self):
        """ Send ping to spacebridge every K seconds where k=self.PING_FREQUENCY_SECONDS"""
        try:
            self.sendPing()
            self.logger.info("Sent Ping, self={}".format(id(self)))
        except Exception as e:
            self.logger.exception("Exception sending ping to cloud gateway")

        self.ping_call_id = asyncio.get_event_loop().call_later(self.PING_FREQUENCY_SECONDS, self.ping_spacebridge)

    def check_spacebridge_pings(self):
        """
        Check when was the last time we received a ping from spacebridge. If it exceeds the threshold, force a
        disconnect by stopping the event loop
        """

        current_time = time_utils.get_current_timestamp()
        seconds_since_ping = current_time - self.last_spacebridge_ping

        self.logger.debug("Time since last spacebridge ping current_time={}, last_spacebridge_ping={}, "
                          "seconds_since_ping={} seconds, self={}"
                          .format(current_time, self.last_spacebridge_ping, seconds_since_ping, id(self)))

        if seconds_since_ping > self.SPACEBRIDGE_RECONNECT_THRESHOLD_SECONDS:
            self.logger.info("Seconds since last ping exceeded threshold. Attempting to reestablish connection with spacebridge")

            if hasattr(self, 'ping_call_id') and self.ping_call_id:
                self.ping_call_id.cancel()

            if hasattr(self, 'check_spacebridge_ping_id') and self.check_spacebridge_ping_id:
                self.check_spacebridge_ping_id.cancel()

            # Explicitly close websocket connection
            self.logger.debug("Closing websocket connection...{}".format(id(self)))
            self.sendClose()

        else:
            self.check_spacebridge_ping_id = asyncio.get_event_loop()\
                .call_later(self.SPACEBRIDGE_RECONNECT_THRESHOLD_SECONDS, self.check_spacebridge_pings)

