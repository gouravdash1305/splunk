"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for the 2nd part of the Spacebridge registration process: completing device pairing
"""

import sys
import json
import base64
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))

from spacebridgeapp.util.splunk_utils.common import get_current_context
from spacebridgeapp.rest.util.errors import SpacebridgePermissionsError
from spacebridgeapp.util import py23
import asyncio
import requests
import splunk.rest as rest
from spacebridgeapp.util import py23
from cloudgateway.registration import pair_device
from cloudgateway.device import DeviceInfo, EnvironmentMetadata
from cloudgateway.auth import SimpleUserCredentials
from cloudgateway.splunk.asyncio.auth import SplunkAuthHeader
from cloudgateway.splunk.encryption import SplunkEncryptionContext
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.data.telemetry_data import InstallationEnvironment
from spacebridgeapp.rest.clients.async_client_factory import AsyncClientFactory
from spacebridgeapp.util import constants
from spacebridgeapp.util.config import secure_gateway_config as config
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.rest.services.splunk_service import get_deployment_info
from spacebridgeapp.rest.config.app import retrieve_state_of_app
from spacebridgeapp.rest.util.helper import extract_parameter
from spacebridgeapp.rest.config.deployment_info import get_deployment_friendly_name
from spacebridgeapp.request.request_processor import BasicAuthHeader, SplunkAuthHeader
from splapp_protocol.request_pb2 import VersionGetResponse
from spacebridgeapp.versioning import app_version, minimum_build
from spacebridgeapp.request.generic_request_processor import fetch_registered_apps
from spacebridgeapp.util.asyncio import cancel_all_tasks
from spacebridgeapp.rest.registration.registration_webhook import validate_user

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "rest_registration_confirmation")

BODY_LABEL = 'body'
QUERY_LABEL = 'query'
AUTH_CODE_LABEL = 'auth_code'
USERNAME_LABEL = 'username'
PASSWORD_LABEL = 'password'
DEVICE_NAME_LABEL = 'device_name'
DEVICE_ID_LABEL = 'device_id'
DEVICE_TYPE_LABEL = 'device_type'
KVSTORE_TEMPORARY_ID_LABEL = 'temp_key'

DEVICE_REGISTRATION_ATTRS = ['device_name', 'device_type', 'device_id', 'app_id', 'app_name', 'platform']
DEVICE_PUBLIC_KEYS_ATTRS = ['encrypt_public_key', 'sign_public_key']


class CompletePairingHandler(BaseRestHandler, PersistentServerConnectionApplication):
    """
    Main class for handling REST Registration endpoint. Subclasses the spacebridge_app
    BaseRestHandler. This multiple inheritance is an unfortunate neccesity based on the way
    Splunk searches for PersistentServerConnectionApplications
    """

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)
        self.base_uri = rest.makeSplunkdUri()
        self.async_client_factory = AsyncClientFactory(self.base_uri)

    def post(self, request):
        auth_code = extract_parameter(request['query'], AUTH_CODE_LABEL, QUERY_LABEL)
        user = request['session']['user']
        session_token = request['session']['authtoken']
        system_authtoken = request['system_authtoken']
        body = json.loads(request['payload'])

        return handle_confirmation(auth_code, user, session_token, system_authtoken, body, self.async_client_factory)


def handle_confirmation(auth_code, user, session_token, system_authtoken, body, async_client_factory):
    """
    Handler for the final DevicePairingConfirmationRequest call. This function:
        1. Authenticates the supplied username and password
        2. Retrieves temporary record from the kvstore
        3. Checks if app_type has been disabled since registration
        4. Makes the DevicePairingConfirmationRequest request to the server
        5. Creates a new permanent record for the device in the kvstore
        6. Deletes the temporary kvstore record

    :param auth_code: User-entered authorization code to be returned to Spacebridge
    :param body: Parsed JSON body of the incoming POST request
    :param kvstore_unconfirmed: Access object for the temporary registration kvstore
    :param system_authtoken: System-level access token for writing to the kvstore
    :return: Success message
    """

    # Authenticates the supplied username and password
    kvstore_temp = KvStore(constants.UNCONFIRMED_DEVICES_COLLECTION_NAME, system_authtoken, owner=user)
    encryption_context = SplunkEncryptionContext(system_authtoken, constants.SPACEBRIDGE_APP_NAME)
    username = extract_parameter(body, USERNAME_LABEL, BODY_LABEL)
    password = extract_parameter(body, PASSWORD_LABEL, BODY_LABEL)

    registration_webhook_url = config.get_registration_webhook_url()

    if registration_webhook_url:
        LOGGER.info('Attempt to validate user via registration webhook')
        validate_user(registration_webhook_url, username, config.get_webhook_verify_ssl())
        LOGGER.info('Successfully validated that user via registration webhook')

    try:
        # use what Splunk thinks the username is to generate the session token
        auth = BasicAuthHeader(username, password)
        content = get_current_context(auth)
        username = content[constants.ENTRY][0][constants.CONTENT][constants.USERNAME]
    except SpacebridgePermissionsError as e:
        LOGGER.exception('Invalid credentials passed to current-context API')
        raise e

    LOGGER.info('Received new registration confirmation request by user=%s for device_owner=%s' % (user, username))

    # Retrieves temporary record from the kvstore
    temp_key = extract_parameter(body, KVSTORE_TEMPORARY_ID_LABEL, BODY_LABEL)
    r, temp_record = kvstore_temp.get_item_by_key(temp_key)
    temp_record = json.loads(temp_record)

    device_id = temp_record[DEVICE_ID_LABEL]
    device_id_raw = base64.b64decode(device_id)

    device_registration = {'_key': py23.urlsafe_b64encode_to_str(device_id_raw)}
    device_public_keys = {'_key': py23.urlsafe_b64encode_to_str(device_id_raw)}

    for k in temp_record.keys():
        if k in DEVICE_REGISTRATION_ATTRS:
            device_registration[k] = temp_record[k]
        if k in DEVICE_PUBLIC_KEYS_ATTRS:
            device_public_keys[k] = temp_record[k]

    # Checks if app_type has been disabled since registration
    app_name = temp_record[DEVICE_TYPE_LABEL]

    device_encryption_info = DeviceInfo(
        base64.b64decode(temp_record['encrypt_public_key']),
        base64.b64decode(temp_record['sign_public_key']),
        base64.b64decode(temp_record['device_id']),
        "NA",
        app_id=temp_record['app_id'],
        app_name=temp_record['device_type']
    )

    deployment_friendly_name = get_deployment_friendly_name(system_authtoken)
    credentials = SimpleUserCredentials(username, password)

    version_get_response = VersionGetResponse()
    try:
        version_get_response = build_version_get_response(session_token, device_encryption_info.app_id,
                                                          temp_record[DEVICE_NAME_LABEL], async_client_factory)

    except Exception as e:
        LOGGER.exception("exception fetching environment metadata")

    env_metadata = EnvironmentMetadata(version_get_response.SerializeToString(),
                                       "{}.{}".format(constants.SPLAPP_APP_ID, constants.VERSION_GET_RESPONSE))

    pair_device(auth_code, credentials, device_encryption_info, encryption_context,
                server_name=deployment_friendly_name, config=config, server_app_id=constants.SPLAPP_APP_ID,
                env_metadata=env_metadata)

    # Creates a new permanent record for the device in the kvstore
    kvstore_user = KvStore(constants.REGISTERED_DEVICES_COLLECTION_NAME, system_authtoken, owner=username)
    kvstore_user.insert_single_item(device_registration)

    # Adds the user to the list of users with registered devices, if not already there
    kvstore_users = KvStore(constants.REGISTERED_USERS_COLLECTION_NAME, system_authtoken)
    kvstore_users.insert_or_update_item_containing_key({'_key': username})

    kvstore_nobody = KvStore(constants.DEVICE_PUBLIC_KEYS_COLLECTION_NAME, system_authtoken)
    kvstore_nobody.insert_single_item(device_public_keys)

    # Deletes the temporary kvstore record
    kvstore_temp.delete_item_by_key(temp_key)

    LOGGER.info('Device registration confirmed. Device with device_name=\"%s\" was recorded in the kvstore.' %
                temp_record[DEVICE_NAME_LABEL])

    return {
        'payload': 'Device registration successful',
        'status': 201,
    }


def build_version_get_response(session_token, app_id, device_name, async_client_factory):
    """
    Build version get response object
    """
    splapp_meta = get_deployment_info(session_token)
    auth_header = SplunkAuthHeader(session_token)
    try:
        loop = asyncio.get_event_loop()
    except:
        LOGGER.debug("Unable to get event loop. Creating a new loop.")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    version_get_response = VersionGetResponse()

    # Deployment Friendly Name
    version_get_response.deploymentFriendlyName = splapp_meta['friendly_name']

    # SSG version and min client version
    version_get_response.cloudgatewayAppVersion = str(app_version())
    version_get_response.minimumClientVersion = str(minimum_build(app_id))

    # Device name
    version_get_response.deviceName = device_name

    # Companion Apps
    companion_app_list = loop.run_until_complete(
        fetch_registered_apps(auth_header, async_client_factory.splunk_client()))

    for key, app in companion_app_list.items():
        companion = version_get_response.companionApps.add()
        companion.appId = key
        companion.appVersion = app[constants.VERSION]

    # Splunk Version
    splunk_version = loop.run_until_complete(
        async_client_factory.telemetry_client().get_splunk_version(auth_header))
    version_get_response.splunkVersion = splunk_version

    # Telemetry Instance Id
    telemetry_instance_id = loop.run_until_complete(
        async_client_factory.telemetry_client().get_telemetry_instance_id(auth_header))
    version_get_response.instanceId = telemetry_instance_id

    # Installation Environment
    installation_environment = loop.run_until_complete(
        async_client_factory.telemetry_client().get_installation_environment(auth_header))

    installation_environment_proto = VersionGetResponse.CLOUD \
        if installation_environment is InstallationEnvironment.CLOUD \
        else VersionGetResponse.ENTERPRISE
    version_get_response.installationEnvironment = installation_environment_proto

    # Clean up any pending tasks
    cancel_all_tasks(loop, LOGGER)


    LOGGER.info("complete building metainfo version_get_response={}".format(version_get_response))
    return version_get_response
