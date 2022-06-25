"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for accessing and setting app_list kvstore records
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))

from spacebridgeapp.messages.request_context import RequestContext
from spacebridgeapp.request.app_list_request_processor import fetch_app_names
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader

from http import HTTPStatus
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.rest import async_base_endpoint
from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, AUTHTOKEN, \
    SESSION, USER, DISPLAY_APP_NAME, APP_NAME, PAYLOAD, STATUS

LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + ".log", "rest_app_list")


class AllApps(async_base_endpoint.AsyncBaseRestHandler):
    """
    Main class for handling the app_list endpoint. Subclasses the spacebridge_app
    BaseRestHandler.

    """

    async def get(self, request):
        """
        REST handler to fetch all apps visible to current user
        """
        authtoken = request[SESSION][AUTHTOKEN]
        user = request[SESSION][USER]
        auth_header = SplunkAuthHeader(authtoken)
        request_context = RequestContext(auth_header, current_user=user, system_auth_header=auth_header)

        async_splunk_client = self.async_client_factory.splunk_client()
        app_list = await fetch_app_names(request_context, async_splunk_client)
        payload = [{APP_NAME: app.app_name, DISPLAY_APP_NAME: app.display_app_name} for app in app_list]
        return {
            PAYLOAD: payload,
            STATUS: HTTPStatus.OK,
        }


