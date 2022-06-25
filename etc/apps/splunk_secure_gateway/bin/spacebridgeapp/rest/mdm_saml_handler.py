"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for the Spacebridge SAML MDM registration process
"""
import base64
import json
import os
import sys
from functools import partial

os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))

from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as kvstore
from spacebridgeapp.rest.services.splunk_service import update_or_create_sensitive_data, fetch_sensitive_data
from cloudgateway.private.encryption.encryption_handler import sign_verify, sign_detached, encrypt_for_send, \
    decrypt_for_receive, decrypt_session_token
from cloudgateway.private.sodium_client import SodiumClient
from cloudgateway.encryption_context import EncryptionContext, generate_keys
from cloudgateway.device import EncryptionKeys
from cloudgateway.splunk.encryption import SplunkEncryptionContext
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader
from cloudgateway.splunk.auth import SplunkJWTCredentials
from spacebridgeapp.util import constants, py23
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.rest import async_base_endpoint
from spacebridgeapp.rest.util.helper import extract_parameter
from spacebridgeapp.util.constants import SESSION, AUTHTOKEN, MDM_SIGN_PUBLIC_KEY, \
    USER_META_COLLECTION_NAME, USER, MDM_KEYPAIR_GENERATION_TIME, \
    SIGN_PUBLIC_KEY, SIGN_PRIVATE_KEY, CREATED, MDM_SIGN_PRIVATE_KEY, SYSTEM_AUTHTOKEN, PAYLOAD
from http import HTTPStatus
from spacebridgeapp.request.request_processor import async_is_valid_session_token
from spacebridgeapp.util.config import secure_gateway_config as config
from spacebridgeapp.rest.registration.registration_webhook import validate_user

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "rest_registration_saml")

BODY_LABEL = 'body'
QUERY_LABEL = 'query'
AUTH_CODE_LABEL = 'auth_code'
USERNAME_LABEL = 'username'
PASSWORD_LABEL = 'password'
SESSION_KEY_LABEL = 'session_key'
DEVICE_NAME_LABEL = 'device_name'
DEVICE_ID_LABEL = 'device_id'
DEVICE_TYPE_LABEL = 'device_type'
KVSTORE_TEMPORARY_ID_LABEL = 'temp_key'
PUBLIC_KEY_LABEL = 'public_key'
MDM_SIGNATURE_LABEL = 'mdm_signature'

DEVICE_REGISTRATION_ATTRS = ['device_name', 'device_type', 'device_id', 'app_id']
DEVICE_PUBLIC_KEYS_ATTRS = ['encrypt_public_key', 'sign_public_key']


class MdmSamlHandler(async_base_endpoint.AsyncBaseRestHandler):
    """
    Main class for handling REST SAML Registration endpoint. Subclasses the spacebridge_app
    AsyncBaseRestHandler
    """

    async def post(self, request):
        user = request[SESSION][USER]
        system_authtoken = request[SYSTEM_AUTHTOKEN]
        body = json.loads(request[PAYLOAD])
        mdm_signing_bundle = get_mdm_signing_bundle(system_authtoken)
        result = await self.handle_saml_mdm_request(user, request, system_authtoken, mdm_signing_bundle, body)

        return result

    async def handle_saml_mdm_request(self, user, request, system_authtoken, mdm_signing_bundle, body):
        """
        Handles the MDM SAML Registration Request.
        Validates signature sent from client, validates session token, generates a JWT token,
        and sends it encrypted using splapp's keys and the client public key
        :param user: string provided by rest handler
        :param session_token: string
        :param system_authtoken: string
        :param mdm_signing_bundle: Object
        :param body: JSON
        :return: Reponse object with payload and status
        """
        registration_webhook_url = config.get_registration_webhook_url()

        if registration_webhook_url:
            LOGGER.info('Attempt to validate user via registration webhook')
            validate_user(registration_webhook_url, user, config.get_webhook_verify_ssl())
            LOGGER.info('Successfully validated that user via registration webhook')

        public_key = base64.b64decode(extract_parameter(body, PUBLIC_KEY_LABEL, BODY_LABEL))
        mdm_signature = base64.b64decode(extract_parameter(body, MDM_SIGNATURE_LABEL, BODY_LABEL))

        client_keys = EncryptionKeys(None, None, public_key, None)
        client_encryption_context = EncryptionContext(client_keys)

        try:
            valid_signature = sign_verify(SodiumClient(LOGGER.getChild("sodium_client")),
                                          base64.b64decode(mdm_signing_bundle['sign_public_key'].encode('utf8')),
                                          client_encryption_context.encrypt_public_key(),
                                          mdm_signature)
        except Exception as e:
            LOGGER.exception("Exception verifying signature from client for user={}".format(user))
            return {
                'payload': {
                    'token': "",
                    'user': user,
                    'status': HTTPStatus.UNAUTHORIZED
                },
                'status': HTTPStatus.OK
            }

        async_splunk_client = self.async_client_factory.splunk_client()
        port_number = await get_http_port_number(async_splunk_client, system_authtoken)
        session_token = get_session_token_from_request(request, port_number)
        valid_request = await async_is_valid_session_token(user, session_token, async_splunk_client)

        LOGGER.info("Received new mdm registration request by user={}".format(user))

        if valid_signature and valid_request:
            try:
                credentials = SplunkJWTCredentials(user)
                credentials.load_jwt_token(SplunkAuthHeader(system_authtoken))
                LOGGER.info("Successfully fetched jwt token")
            except Exception as e:
                LOGGER.exception("Exception fetching jwt token for user={} with message={}".format(user, e))
                return {
                    'payload': {
                        'token': "",
                        'user': user,
                        'status': HTTPStatus.UNPROCESSABLE_ENTITY
                    },
                    'status': HTTPStatus.OK
                }

            splapp_encryption_context = SplunkEncryptionContext(system_authtoken,
                                                                constants.SPACEBRIDGE_APP_NAME,
                                                                SodiumClient(LOGGER.getChild("sodium_client")))

            jwt_credentials = credentials.get_credentials() if sys.version_info < (3, 0) else str.encode(
                credentials.get_credentials())
            # Encrypt session token using splapp keys
            secured_session_token = splapp_encryption_context.secure_session_token(jwt_credentials)
            # Encrypt session token using client's given public key
            encrypted_jwt_token = encrypt_for_send(SodiumClient(LOGGER.getChild("sodium_client")),
                                                         client_encryption_context.encrypt_public_key(),
                                                         secured_session_token)
            base64_encrypted_jwt_token = py23.b64encode_to_str(encrypted_jwt_token)

            return {
                'payload': {
                    'token': base64_encrypted_jwt_token,
                    'user': user,
                    'status': HTTPStatus.OK
                },
                'status': HTTPStatus.OK
            }
        else:
            LOGGER.info("Error: Mismatched user={} and session token".format(user))
            return {
                'payload': {
                    'token': "",
                    'user': user,
                    'status': HTTPStatus.UNAUTHORIZED
                },
                'status': HTTPStatus.OK
            }


def get_session_token_from_request(request, port_number):
    key = f'splunkd_{port_number}'
    cookies = request[constants.COOKIES]
    cookies_obj = {}
    for c in cookies:
        cookies_obj[c[0]] = c[1]
    return cookies_obj[key]


def get_mdm_signing_bundle(system_authtoken):
    """
    Method to fetch that the mdm signing bundle for this instance
    :param request: Object
    :return: Object
    """
    response = {}
    public_key = fetch_sensitive_data(system_authtoken, MDM_SIGN_PUBLIC_KEY)
    private_key = fetch_sensitive_data(system_authtoken, MDM_SIGN_PRIVATE_KEY)
    response.update({'sign_public_key': public_key, 'sign_private_key': private_key})

    return response


async def get_http_port_number(async_splunk_client, system_authtoken):
    response = await async_splunk_client.async_get_server_settings(SplunkAuthHeader(system_authtoken))
    response_json = await response.json()
    http_port_number = response_json[constants.ENTRY][0][constants.CONTENT][constants.HTTP_PORT]
    return http_port_number
