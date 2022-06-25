"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.
"""

import json
import sys
import time
import splunk

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))

from spacebridgeapp.util import py23
from cloudgateway.splunk.encryption import SplunkEncryptionContext
from cloudgateway.private.sodium_client import SodiumClient
from http import HTTPStatus
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util import constants
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.rest.services.splunk_service import fetch_sensitive_data
from spacebridgeapp.versioning import app_version
from spacebridgeapp.util.config import secure_gateway_config as config
from spacebridgeapp.util.kvstore import retry_until_ready_sync
from spacebridgeapp.util.word_list import random_words

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "rest_app_config")


class DeploymentInfo(BaseRestHandler, PersistentServerConnectionApplication):
    """
    Main class for handling the devices_user endpoint. Subclasses the spacebridge_app
    BaseRestHandler.
    """

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def get(self, request):
        try:
            auth_token = request['system_authtoken']
            friendly_name = get_deployment_friendly_name(auth_token)
            encryption_context = SplunkEncryptionContext(auth_token, constants.SPACEBRIDGE_APP_NAME, SodiumClient(LOGGER))
            mdm_sign_public_key = get_mdm_public_signing_key(auth_token)
            mdm_keypair_generation_time = get_mdm_update_timestamp(request, auth_token)
            return {
                constants.PAYLOAD: {
                    constants.DEPLOYMENT_FRIENDLY_NAME: friendly_name,
                    constants.SIGN_PUBLIC_KEY: py23.b64encode_to_str(encryption_context.sign_public_key()),
                    constants.DEPLOYMENT_ID: encryption_context.sign_public_key(
                        transform=encryption_context.generichash_hex),
                    constants.ENCRYPT_PUBLIC_KEY: py23.b64encode_to_str(encryption_context.encrypt_public_key()),
                    constants.SERVER_VERSION: str(app_version()),
                    constants.MDM_SIGN_PUBLIC_KEY: mdm_sign_public_key,
                    constants.MDM_KEYPAIR_GENERATION_TIME: mdm_keypair_generation_time
                },
                constants.STATUS: HTTPStatus.OK
            }
        except Exception as e:
            LOGGER.exception('An error occurred fetching deployment info')
            raise e

def get_mdm_public_signing_key(auth_token):
    """
    Return the current MDM public signing key

    :param auth_token: A valid splunk system auth token
    :return: The current friendly deployment name, None if not set
    """

    try:
        return fetch_sensitive_data(auth_token, constants.MDM_SIGN_PUBLIC_KEY)
    except splunk.ResourceNotFound as e:
        LOGGER.info("Mdm public key not found in storage/passwords")
        return None


def get_mdm_update_timestamp(request, auth_token, retry=False):
    """
    Return the generation time of the mdm signing public key
    :param auth_token: A valid splunk system auth token
    :return: The last time a mdm public signing key was generated (epoch time)
    """
    kvstore = KvStore(constants.USER_META_COLLECTION_NAME, auth_token, owner=request[constants.SESSION][constants.USER])
    parsed = {}
    try:
        r, jsn = kvstore.get_item_by_key(constants.MDM_KEYPAIR_GENERATION_TIME)
        parsed = json.loads(jsn)

        LOGGER.info("mdm keypair last generated info={}".format(parsed[constants.TIMESTAMP]))
    except splunk.RESTException as e:
        # If we get a 503, KV Store is not up yet, so try again in 5 seconds.
        if e.statusCode == HTTPStatus.SERVICE_UNAVAILABLE:
            if not retry:
                time.sleep(5)
                return get_mdm_update_timestamp(auth_token, True)

        if e.statusCode != HTTPStatus.NOT_FOUND:
            raise e

    return parsed.get(constants.TIMESTAMP, None)


def get_deployment_friendly_name(auth_token, retry=False):
    """
    Return the current splunk deployment friendly name.
    :param auth_token: A valid splunk system auth token
    :return: The current friendly deployment name, None if not set
    """
    kvstore = KvStore(constants.META_COLLECTION_NAME, auth_token, owner=constants.NOBODY)

    parsed = {}
    try:
        r, jsn = kvstore.get_item_by_key(constants.DEPLOYMENT_INFO)
        parsed = json.loads(jsn)

        LOGGER.info("current deployment info=%s" % str(parsed))
    except splunk.RESTException as e:
        # If we get a 503, KV Store is not up yet, so try again in 5 seconds.
        if e.statusCode == HTTPStatus.SERVICE_UNAVAILABLE:
            if not retry:
                time.sleep(5)
                return get_deployment_friendly_name(auth_token, True)

        if e.statusCode != HTTPStatus.NOT_FOUND:
            raise e

    return parsed.get(constants.DEPLOYMENT_FRIENDLY_NAME, "")


def set_deployment_friendly_name(auth_token, name):
    """
    Given an auth token and name, set the deployment friendly name in the 'meta' collection
    :param auth_token: A valid splunk system auth token
    :param name: the string representation of the mame you want to give the deployment
    :return:
    """
    kvstore = KvStore(constants.META_COLLECTION_NAME, auth_token, owner=constants.NOBODY)

    deployment_info = {'_key': constants.DEPLOYMENT_INFO, constants.DEPLOYMENT_FRIENDLY_NAME: name}

    kvstore.insert_or_update_item_containing_key(deployment_info)


def ensure_deployment_friendly_name(auth_token):
    """
    On first load, randomly pick 3 words from word list to come up with name.
    Will not return until the deployment friendly name is set.

    :param auth_token: A valid splunk system auth token
    :return:
    """
    def fetch():
        return get_deployment_friendly_name(auth_token)

    name = retry_until_ready_sync(fetch)

    if not name:
        name = ''.join(random_words(3))
        LOGGER.info("Deployment friendly name not set, new_name={}".format(name))
        set_deployment_friendly_name(auth_token, name)
    else:
        LOGGER.info("Using deployment friendly name=%s" % name)
