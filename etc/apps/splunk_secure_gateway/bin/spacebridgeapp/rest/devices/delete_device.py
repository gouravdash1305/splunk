"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for deleting a specific device
"""

import sys
import json
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
from spacebridgeapp.util import py23

from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util import constants
from spacebridgeapp.util.config import secure_gateway_config as config
from spacebridgeapp.util.mtls import build_key_bundle
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.util.helper import extract_parameter
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.rest.services.spacebridge_service import delete_device_from_spacebridge
from spacebridgeapp.rest.services.splunk_service import get_devices_for_user, user_has_registered_devices

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "rest_delete_device")
DEVICE_KEY_LABEL = 'device_key'


class DeleteDevice(BaseRestHandler, PersistentServerConnectionApplication):
    """
    Main rest handler class for the delete device functionality
    """

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def post(self, request):
        """
        Deletes the specified device from the kvstore. Parses necessary data and credentials
        out of the request object, validates permissions, and makes the deletion request.

        Uses POST because DELETE method doesn't work from the Splunk UI
        """
        user = request['session']['user']
        device_owner = user
        if 'device_owner' in request['query'] and py23.py2_check_unicode(request['query']['device_owner']):
            device_owner = request['query']['device_owner']
        device_key = extract_parameter(request['query'], DEVICE_KEY_LABEL, 'query')
        system_authtoken = request['system_authtoken']
        user_authtoken = request['session']['authtoken']

        key_bundle = None
        if config.get_mtls_enabled():
            key_bundle = build_key_bundle(system_authtoken)

        LOGGER.info('Deleting device_key=%s in kvstore of device_owner=%s for user=%s'
                    % (device_key, device_owner, user))

        return delete_device(user, device_owner, device_key, system_authtoken, user_authtoken, key_bundle)


def delete_device(user, device_owner, device_key, system_authtoken, user_authtoken, key_bundle=None):
    """
    Deletes a specific device from the kvstore. This function:
        1. Checks if the user has the necessary privileges to delete the given device
        2. Attempts to delete the device from the kvstore

    :param user: User making the deletion request
    :param device_owner: User who owns the device being deleted
    :param device_key: kvstore _key of the device being deleted
    :param system_authtoken: Authorization token with system-level privileges. Used to allow users to delete
    their own devices even when they don't have unrestricted kvstore write access
    :param user_authtoken: Authorization token with the same permissions as "user"
    :return: Success message
    """

    # Checks if the user has the necessary privileges to delete the given device
    kvstore_user = KvStore(constants.REGISTERED_DEVICES_COLLECTION_NAME, user_authtoken, owner=device_owner)
    if user == device_owner:
        kvstore_user = KvStore(constants.REGISTERED_DEVICES_COLLECTION_NAME, system_authtoken, owner=device_owner)

    kvstore_nobody = KvStore(constants.DEVICE_PUBLIC_KEYS_COLLECTION_NAME, system_authtoken)

    r, record = kvstore_user.get_item_by_key(device_key)
    record = json.loads(record)

    # Attempts to delete the device from the kvstore
    kvstore_user.delete_item_by_key(device_key)
    try:
        kvstore_nobody.delete_item_by_key(device_key)
    except splunk.RESTException:
        LOGGER.info("public for device not found, device_id=%s" % device_key)

    LOGGER.info('device_key=%s (of device_owner=%s) deleted from kvstore by user=%s' % (device_key, device_owner, user))

    delete_device_from_spacebridge(record['device_id'], system_authtoken, key_bundle)
    LOGGER.info(
        'device key=%s (of device_owner=%s) deleted from spacebridge by user=%s', device_key, device_owner, user)

    if not user_has_registered_devices(device_owner, system_authtoken):
        kvstore_nobody = KvStore(constants.REGISTERED_USERS_COLLECTION_NAME, system_authtoken)
        kvstore_nobody.delete_item_by_key(device_owner)

    return {
        'payload': 'Device with key %s successfully deleted' % device_key,
        'status': 200,
    }
