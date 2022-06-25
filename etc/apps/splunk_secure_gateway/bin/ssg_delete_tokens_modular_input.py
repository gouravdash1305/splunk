"""
Copyright (C) 2009-2021 Splunk Inc. All Rights Reserved.

Modular Input for deleting expired tokens created by Splunk Secure Gateway
"""
import json
import warnings

warnings.filterwarnings('ignore', '.*service_identity.*', UserWarning)

import sys
import os
from splunk.clilib.bundle_paths import make_splunkhome_path
from spacebridgeapp.util import py23, constants


os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

import splunk
import time
from http import HTTPStatus
from spacebridgeapp.util.base_modular_input import BaseModularInput
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util.splunk_utils.common import modular_input_should_run
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME
from spacebridgeapp.rest.services.splunk_service import get_splunk_auth_type, get_all_secure_gateway_tokens, \
    delete_token_by_id
from spacebridgeapp.util.time_utils import get_current_timestamp
from cloudgateway.private.util.tokens_util import calculate_token_info
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader
from spacebridgeapp.rest.services.splunk_service import get_all_mobile_users

LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + '.log', 'ssg_delete_tokens_modular_input.app')

TIMEOUT_SECONDS = 5


class DeleteTokensModularInput(BaseModularInput):
    title = 'Splunk Secure Gateway Deleting Expired Tokens'
    description = 'Delete expired or invalid tokens created by Secure Gateway from Splunk'
    app = 'Splunk Secure Gateway'
    name = 'splunk_secure_gateway'
    use_kvstore_checkpointer = False
    use_hec_event_writer = False
    logger = LOGGER
    input_config_key = "ssg_delete_tokens_modular_input://default"

    def extra_arguments(self):
        """
        Override extra_arguments list for modular_input scheme
        :return:
        """
        return [
            {
                'name': 'param1',
                'description': 'No params required'
            }
        ]

    def do_run(self, input_config):
        """
        Executes the modular input
        :param input_config:
        :return:
        """
        if not super(DeleteTokensModularInput, self).do_run(input_config):
            return

        if not modular_input_should_run(self.session_key, logger=self.logger):
            self.logger.debug("Modular input will not run on this node.")
            return

        auth_type = get_splunk_auth_type(authtoken=self.session_key)
        if auth_type.decode('utf-8') != constants.SAML:
            self.logger.debug("Deleting tokens modular input should not run on a non-SAML environment")
            return

        self.logger.info("Running Delete tokens modular input on search captain node")
        delete_tokens_sync = DeleteTokensSync(self.session_key)

        try:
            delete_tokens_sync.run()
        except:
            self.logger.exception("Failure encountered while running Delete Tokens sync")


class DeleteTokensSync(object):

    def __init__(self, session_key):
        """
        Delete Tokens Sync constructor
        :param session_key: session key passed by modular input
        """
        self.session_key = session_key
        self.system_auth_header = SplunkAuthHeader(self.session_key)

    def run(self):
        """
        Attempts to delete tokens that are expired or invalid created by Secure Gateway from Splunk. If the kvstore
        is not yet available, schedules a non-blocking retry attempt in 5 seconds
        """
        LOGGER.info("Attempting Deleting Invalid Tokens")
        try:
            self.sync()
        except splunk.RESTException as e:
            if e.statusCode == HTTPStatus.SERVICE_UNAVAILABLE:
                LOGGER.info("KVStore is not yet setup. Retrying user sync in 5 seconds")
                time.sleep(TIMEOUT_SECONDS)
                self.run()
            else:
                raise e

    def sync(self):
        """
        Gets all registered users. Gets all tokens per user, sorted by expiry date. Deletes all tokens except the one
        with the most recent expiration date and any that are being used as subscription credentials.
        """

        all_registered_users = get_all_mobile_users(self.session_key)
        try:
            for user in all_registered_users:
                tokens = get_all_secure_gateway_tokens(self.session_key, user)
                current_time = get_current_timestamp()

                index_to_delete = min(3, len(tokens))
                for i in range(0, index_to_delete - 1):
                    if tokens[i]['content']['claims']['exp'] < current_time:
                        index_to_delete = i
                        break

                tokens_to_delete = tokens[index_to_delete:]

                kvstore_subscription_credentials = KvStore(constants.SUBSCRIPTION_CREDENTIALS_COLLECTION_NAME,
                                                           self.session_key, owner=user)
                response, credentials = kvstore_subscription_credentials.get_all_items()
                credentials = json.loads(credentials)
                jwt_credential = [c for c in credentials if
                                  'session_type' in c and c['session_type'] == constants.JWT_TOKEN_TYPE[0]]
                if jwt_credential:
                    subscription_token_info = calculate_token_info(jwt_credential['session_key'])
                else:
                    subscription_token_info = None

                for token in tokens_to_delete:
                    # if that token does not exist in subscription credentials
                    if not subscription_token_info or token['name'] != subscription_token_info['id']:
                        delete_token_by_id(self.session_key, user, token['name'])
        except:
            LOGGER.exception("Exception performing DeleteTokensSync")


if __name__ == "__main__":
    worker = DeleteTokensModularInput()
    worker.execute()
