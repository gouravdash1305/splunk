
"""
Copyright (C) 2009-2021 Splunk Inc. All Rights Reserved.

REST endpoint handler for kvstore dashboard client
"""

import base64
import sys
import json
from http import HTTPStatus
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
from spacebridgeapp.util import py23
import splunk.rest as rest
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util import constants
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services.kvstore_service import KVStoreCollectionAccessObject
from spacebridgeapp.rest.debug.util import create_splunk_resp
from spacebridgeapp.util.constants import OWNER, LIMIT, SORT, APP

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "kvstore_dashboard_client")

COLLECTION = "collection"
METHOD = "method"
DELETE_FIELD_NAME = "delete_field_name"
DELETE_FIELD_VALUE = "delete_field_value"
POST_DATA = "post_data"


class KvstoreDashboardClientHandler(BaseRestHandler, PersistentServerConnectionApplication):

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)
        self.base_uri = rest.makeSplunkdUri()

    def get(self, request):
        """
        Perform a test registration and websocket message
        """
        response = {'result': '', 'error': ''}

        user_token = request['session']['authtoken']
        user = request['session']['user']

        try:

            collection = request['query'][COLLECTION]
            owner = request['query'][OWNER]
            app = request['query'][APP]
            method = request['query'][METHOD]
            limit = request['query'][LIMIT]
            sort = request['query'][SORT] if SORT in request['query'] else ""

            if method == constants.GET:
                response['result'] = json.dumps(self.exec_get(owner, collection, app, limit, sort, user_token), indent=3)

            if method == constants.DELETE:
                field_name = request['query'][DELETE_FIELD_NAME]
                field_value = request['query'][DELETE_FIELD_VALUE]
                query = {field_name: field_value}
                result = self.exec_delete(owner, collection, app, query, user_token),
                response['result'] = result

            if method == constants.POST:
                post_data = json.loads(request['query'][POST_DATA])
                result = self.exec_post(owner, collection, app, post_data, user_token)
                response['result'] = result

        except Exception as e:
            LOGGER.exception(str(e))
            response['result'] = str(e)

        return {
            'raw_payload': json.dumps(create_splunk_resp(response)),
            'status': 200
        }



    def exec_get(self, owner, collection, app, limit, sort, auth_token):
        kvstore_client = KVStoreCollectionAccessObject(collection, auth_token, app, owner)
        r, devices = kvstore_client.get_all_items(limit=limit, sort=sort)
        return json.loads(devices)

    def exec_post(self, owner, collection, app, item, auth_token):
        kvstore_client = KVStoreCollectionAccessObject(collection, auth_token, app, owner)
        r, response = kvstore_client.insert_single_item(item)
        if r.status == HTTPStatus.CREATED:
            return 'Successfully inserted item into KvStore with response={}'.format(response)
        else:
            return "Failed to insert with error code={}".format(r.status)

    def exec_delete(self, owner, collection, app, query, auth_token):
        kvstore_client = KVStoreCollectionAccessObject(collection, auth_token, app, owner)
        r, response = kvstore_client.delete_items_by_query(query)
        if r.status == HTTPStatus.OK:
            return 'Successfully deleted entries from KvStore'
        else:
            return "Failed to delete entries with error code={}".format(r.status)
