"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for accessing and setting opt-in signals
"""
import sys
import json
import splunk
from http import HTTPStatus

from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))

from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util.time_utils import get_current_timestamp
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KVStore
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, SESSION, AUTHTOKEN, USER, PAYLOAD, STATUS, \
    META_COLLECTION_NAME, NOBODY, TIMESTAMP, KEY, SYSTEM_AUTHTOKEN


LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + ".log", "opt_in_handler")

OPT_IN = 'opt_in'
TYPE = 'type'

# Currently only support 'soc2' opt-in type by default
SOC2 = 'soc2'


class OptInHandler(BaseRestHandler, PersistentServerConnectionApplication):
    """
    Main class for handling the opt_in endpoint. Subclasses the spacebridge_app
    BaseRestHandler.
    """

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def get(self, request):
        """
        Get the opt_in value by type.  Currently hardcoded to 'soc2' type
        :param request:
        :return:
        """
        try:
            auth_token = request[SESSION][AUTHTOKEN]
            opt_in = get_opt_in(SOC2, auth_token)

            return {
                PAYLOAD: opt_in,
                STATUS: HTTPStatus.OK
            }
        except splunk.RESTException as e:
            return build_error_payload(e)

    def post(self, request):
        """
        Post call to opt-in by type.  Currently hardcoded to 'soc2' type
        :param request:
        :return:
        """
        try:
            # system_auth token required to add key in nobody namespace
            system_authtoken = request[SYSTEM_AUTHTOKEN]
            user = request[SESSION][USER]
            set_opt_in(SOC2, user, system_authtoken)
            return {
                PAYLOAD: {},
                STATUS: HTTPStatus.OK
            }
        except splunk.RESTException as e:
            return build_error_payload(e)


# Package helpers
def build_error_payload(e):
    return {
        PAYLOAD: {
            'message': e.get_message_text(),
            'description': e.get_extended_message_text()
        },
        STATUS: e.statusCode
    }


# Helpers to access KVStore
def get_opt_in(opt_in_type, auth_token):
    """
    Get the opt_in key value by type, None if exception occurs or key record is empty
    :param opt_in_type: Specify the opt-in type will use to construct a opt_in key.  i.e. soc2_opt_in
    :param auth_token:
    :return: payload dict
    """
    # Initialize negative result status
    result = {
        OPT_IN: False,
        TYPE: opt_in_type
    }

    try:
        kvstore = KVStore(META_COLLECTION_NAME, auth_token, owner=NOBODY)
        _, record = kvstore.get_item_by_key(f"{opt_in_type}_opt_in")
    except splunk.RESTException as e:
        if e.statusCode != HTTPStatus.NOT_FOUND:
            raise e
        # opt-in key NOT_FOUND this is a successful negative result
        return result

    # If record for opt-in type exist, update the result dict with params
    if record:
        record = json.loads(record)
        # If record contains keys TIMESTAMP, USERNAME and both have value
        if all(key in record and record[key] for key in [TIMESTAMP, USER]):
            result[TIMESTAMP] = record[TIMESTAMP]
            result[USER] = record[USER]
            result[OPT_IN] = True
    return result


def set_opt_in(opt_in_type, user, auth_token):
    """
    Set opt_in for specified type.  Will insert or update opt_in details.
    :param opt_in_type:
    :param user:
    :param auth_token:
    :return: payload dict
    """
    kvstore = KVStore(META_COLLECTION_NAME, auth_token, owner=NOBODY)
    record = {
        KEY: f"{opt_in_type}_opt_in",
        USER: user,
        TIMESTAMP: get_current_timestamp()
    }
    kvstore.insert_or_update_item_containing_key(record)


def is_opt_in(opt_in_type, auth_token):
    """
    Helper method to return boolean value if type has been opted-in
    :param opt_in_type:
    :param auth_token:
    :return:
    """
    try:
        opt_in = get_opt_in(opt_in_type, auth_token)
        if opt_in and OPT_IN in opt_in and opt_in[OPT_IN]:
            return opt_in
    except splunk.RESTException as e:
        pass
    return False
