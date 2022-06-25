"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for the first part of  Spacebridge registration process: validating an auth code
"""

import sys
import json
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path


sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))
from spacebridgeapp.util import py23

from cloudgateway.splunk.encryption import SplunkEncryptionContext
from cloudgateway.private.sodium_client import SodiumClient
from cloudgateway.registration import authenticate_code


from http import HTTPStatus
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, UNCONFIRMED_DEVICES_COLLECTION_NAME, ADMIN_ALL_OBJECTS, DRONE_MODE
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.rest.util.helper import extract_parameter
from spacebridgeapp.rest.util import errors as Errors
from spacebridgeapp.rest.devices.user_devices import get_devices_for_user
from spacebridgeapp.util.config import secure_gateway_config as config
from spacebridgeapp.util.app_info import resolve_app_name, APP_ID_TO_PLATFORM_MAP, get_app_platform
from spacebridgeapp.rest.registration.registration_webhook import validate_user

LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + ".log", "rest_registration_query")

QUERY_LABEL = 'query'
AUTH_CODE_LABEL = 'auth_code'
DEVICE_NAME_LABEL = 'device_name'
DEVICE_ID_LABEL = 'device_id'
APP_TYPE_LABEL = 'app_type'
ENCRYPT_PUBLIC_KEY_LABEL = 'encrypt_public_key'
SIGN_PUBLIC_KEY_LABEL = 'sign_public_key'


class ValidateAuthCodeHandler(BaseRestHandler, PersistentServerConnectionApplication):
    """
    Main class for handling REST Registration endpoint. Subclasses the spacebridge_app
    BaseRestHandler. This multiple inheritance is an unfortunate neccesity based on the way
    Splunk searches for PersistentServerConnectionApplications
    """

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def get(self, request):
        auth_code = extract_parameter(request['query'], AUTH_CODE_LABEL, QUERY_LABEL)
        device_name = extract_parameter(request['query'], DEVICE_NAME_LABEL, QUERY_LABEL)
        user = request['session']['user']
        system_authtoken = request['system_authtoken']
        sodium_client = SodiumClient(LOGGER.getChild('sodium_client'))
        encryption_context = SplunkEncryptionContext(system_authtoken, SPACEBRIDGE_APP_NAME, sodium_client)
        kvstore_access_object = KvStore(UNCONFIRMED_DEVICES_COLLECTION_NAME, system_authtoken, owner=user)
        return handle_query(auth_code, device_name, user, system_authtoken, encryption_context, kvstore_access_object)


def handle_query(auth_code, device_name, user, system_authtoken, encryption_context,
                 kvstore_access_object):
    """
    Handler for the initial AuthenticationQueryRequest call. This function:
        1. Makes the AuthenticationQueryRequest request to the server
        2. Checks if app_type has been disabled
        3. Stores a temporary record in the kvstore

    :param auth_code: User-entered authorization code to be returned to Spacebridge
    :param device_name: Name of the new device
    :return: Confirmation code to be displayed to user, and id of temporary kvstore record to be returned later
    """

    LOGGER.info('Received new registration query request by user=%s' % user)

    registration_webhook_url = config.get_registration_webhook_url()

    if registration_webhook_url:
        LOGGER.info('Attempt to validate user via registration webhook')
        validate_user(registration_webhook_url, user, config.get_webhook_verify_ssl())
        LOGGER.info('Successfully validated that user via registration webhook')


    # Makes the AuthenticationQueryRequest request to the server
    client_device_info = authenticate_code(auth_code, encryption_context, resolve_app_name, config=config)
    app_name = client_device_info.app_name
    app_id = client_device_info.app_id

    platform = client_device_info.platform

    # if platform not set and we know platform based on app id, use that.
    if not platform and app_id in APP_ID_TO_PLATFORM_MAP:
        platform = get_app_platform(app_id)

    LOGGER.info("client_device_info={}".format(client_device_info))

    user_devices = get_devices_for_user(user, system_authtoken)
    LOGGER.info("user_devices=%s" % user_devices)

    if any(device[DEVICE_NAME_LABEL] == device_name and device['device_type'] == app_name for device in user_devices):
        err_msg = ('Registration Error: user={} device_name={} of app_type={} already exists'
                   .format(user, device_name, app_name))
        LOGGER.info(err_msg)
        raise Errors.SpacebridgeRestError(err_msg, HTTPStatus.CONFLICT)

    # Stores a temporary record in the kvstore
    kvstore_payload = client_device_info.to_json()
    kvstore_payload['device_name'] = device_name
    kvstore_payload['device_type'] = app_name
    kvstore_payload['app_name'] = app_name
    kvstore_payload['app_id'] = app_id
    kvstore_payload['platform'] = platform
    _, content = kvstore_access_object.insert_single_item(kvstore_payload)


    return {
        'payload': {
            'temp_key': json.loads(content)['_key'],
            'conf_code': client_device_info.confirmation_code
        },
        'status': HTTPStatus.OK,
    }
