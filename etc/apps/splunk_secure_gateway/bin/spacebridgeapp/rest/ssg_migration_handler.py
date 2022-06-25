"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for Splunk Cloud Gateway migration to Splunk Secure Gateway
"""
import sys
import json
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))
from spacebridgeapp.util import py23

from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.migration.migration_script import Migration
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.rest.services.splunk_service import get_app_list_request
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject as KvStore
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader
from spacebridgeapp.rest.services.kvstore_service import get_all_collections
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, ENCRYPTION_KEYS, \
    MDM_SIGN_PUBLIC_KEY, MDM_SIGN_PRIVATE_KEY, CLOUDGATEWAY_APP_NAME, META_COLLECTION_NAME, NOBODY, KEY, \
    MIGRATION_DONE, STATUS, MTLS_KEY, MTLS_CERT, SYSTEM_AUTHTOKEN, DEPLOYMENT_INFO, PAYLOAD
LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + ".log", "ssg_migration_handler")

RUN = "RUN"
STOP = "STOP"
PENDING = "0"
DONE = "1"
CANCELLED = "2"


class MigrationHandler(BaseRestHandler, PersistentServerConnectionApplication):

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def get(self, request):
        system_authtoken = request[SYSTEM_AUTHTOKEN]
        meta_collection = KvStore(META_COLLECTION_NAME, system_authtoken, owner=NOBODY)
        meta_keys = meta_collection.get_collection_keys()
        keys = json.loads(meta_keys[1])
        migration_data = {}
        status = PENDING
        try:
            app_info = get_app_list_request(system_authtoken, CLOUDGATEWAY_APP_NAME)
            if not app_info or app_info['entry'][0]['content']['disabled']:
                status = CANCELLED
            else:
                for dictionary in keys:
                    if MIGRATION_DONE in dictionary.values():
                        migration_data = json.loads(meta_collection.get_item_by_key(MIGRATION_DONE)[1])
                        status = migration_data[STATUS]
                        break

        except Exception as e:
            status = CANCELLED

        return {
            'payload': {
                'status': status,
                'migration': migration_data,
            },
            'status': 200,
        }

    def post(self, request):
        system_authtoken = request[SYSTEM_AUTHTOKEN]
        body = json.loads(request[PAYLOAD])

        if RUN in body:
            worker = Migration(system_authtoken)
            worker.run()
            return {
                'payload': {
                    'RUN': "success",
                },
                'status': 200,
            }
        if STOP in body:
            meta_collection = KvStore(META_COLLECTION_NAME, system_authtoken, owner=NOBODY)
            migration_info = {KEY: MIGRATION_DONE, STATUS: CANCELLED}
            meta_collection.insert_or_update_item_containing_key(migration_info)
            return {
                'payload': {
                    'STOP': "success",
                },
                'status': 200,
            }

    def put(self, request):
        system_authtoken = request[SYSTEM_AUTHTOKEN]
        meta_collection = KvStore(META_COLLECTION_NAME, system_authtoken, owner=NOBODY)
        migration_info = {KEY: MIGRATION_DONE, STATUS: PENDING}
        meta_collection.insert_or_update_item_containing_key(migration_info)
        return {
           'payload': {
               "test": "reset"
           },
           'status': 200,
        }
