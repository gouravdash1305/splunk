"""
Asyncio based messaged handler. Ported from cloudgateway_message_handler to use asyncio
"""

from functools import partial
from spacebridge_protocol import sb_common_pb2
from cloudgateway.private.encryption.encryption_handler import decrypt_for_receive, sign_verify
from cloudgateway.private.messages.parse import parse_signed_envelope, parse_application_message, \
    parse_spacebridge_message

from cloudgateway.private.messages.send import send_response

class AioMessageHandler(object):

    def __init__(self, message_handler, encryption_context, logger):
        """
        Class for specifying behaviour when a message is received from Cloud Gateway
        Args:
            message_handler: IMessageHandler object which specifies how to handle spacebridge and cloudgateway messages
            system_auth_header:  SplunkAuthHeader object which might be necessary to access splunk
            encryption_context: EcnryptionContext object which is necessary for decrypting and encrypting messages
            logger: Logger object for logging purposes
        """
        self.message_handler = message_handler
        self.encryption_context = encryption_context
        self.logger = logger


    async def on_message(self, msg, websocket_protocol):
        """
        Parses a signed envelope, decrypts the payload and delegates handling of the payload to the message_handler.

        If message_handler returns either a ServerResponse object, or List of ServerResponse, we send these responses
        to cloud gateway

        Args:
            msg: Serialized Signed Envelope to cloud gateway
            websocket_protocol: AioClientProtocol

        """

        signed_envelope = parse_signed_envelope(msg, self.logger)

        if signed_envelope.messageType == sb_common_pb2.SignedEnvelope.MESSAGE_TYPE_APPLICATION_MESSAGE:
            self.logger.info("message=RECEIVED_ENVELOPE type=application_message")
            try:
                # Parse application message
                application_message = parse_application_message(signed_envelope.serialized, self.logger)
                message_sender = application_message.sender
                request_id = application_message.id

                # Decrypt payload
                device_encryption_info = await self.message_handler.fetch_device_info(message_sender)


                decrypted_application_msg_payload = self.decrypt_application_msg_payload(application_message,
                                                                                         signed_envelope,
                                                                                         device_encryption_info)

                # Delegate handling of application message to handler
                response = await self.message_handler.handle_application_message(decrypted_application_msg_payload,
                                                                                  message_sender, request_id)

                # Send response back if necessary
                if isinstance(response, (list,)):
                    self.logger.debug("sending list of size={} back to sender, request_id={}".format(len(response),
                                                                                                     request_id))
                    for r in response:
                        send_response(r, device_encryption_info, websocket_protocol, self.logger)

                elif hasattr(response, 'payload') and hasattr(response, 'request_id'):
                    self.logger.debug("sending single response back to sender, request_id={}".format(request_id))
                    send_response(response, device_encryption_info, websocket_protocol, self.logger)

                return response
            except Exception as e:
                self.logger.exception("Exception handling application message={}".format(e))

        elif signed_envelope.messageType == sb_common_pb2.SignedEnvelope.MESSAGE_TYPE_SPACEBRIDGE_MESSAGE:
            self.logger.info("message=RECEIVED_ENVELOPE type=spacebridge_message")

            spacebridge_message = parse_spacebridge_message(signed_envelope.serialized, self.logger)

            await self.message_handler.handle_cloudgateway_message(spacebridge_message)
            return True
        else:
            self.logger.info("message=RECEIVED_ENVELOPE type=%s" % str(signed_envelope.messageType))
            return "Unknown message type"



    def decrypt_application_msg_payload(self, application_msg, signed_envelope, device_encryption_info):
        """
        Decrypt incoming application message and return the decrypted playload
        """

        sender_sign_public_key = device_encryption_info.sign_public_key
        encryption_context = self.encryption_context
        sodium_client = encryption_context.sodium_client

        decryptor = partial(decrypt_for_receive,
                            sodium_client,
                            encryption_context.encrypt_public_key(),
                            encryption_context.encrypt_private_key())

        if not sign_verify(sodium_client, sender_sign_public_key, signed_envelope.serialized,
                           signed_envelope.signature):
            return "Signature validation failed"

        encrypted_payload = application_msg.payload
        decrypted_payload = decryptor(encrypted_payload)

        return decrypted_payload
