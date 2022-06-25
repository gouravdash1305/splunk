"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for accessing and setting app_list kvstore records
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))

from http import HTTPStatus
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.rest import async_base_endpoint
from spacebridgeapp.messages.request_context import RequestContext
from spacebridgeapp.request.app_list_request_processor import fetch_dashboard_app_list_with_default, fetch_app_names, \
    set_dashboard_app_list

from spacebridgeapp.exceptions.spacebridge_exceptions import SpacebridgeApiRequestError
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader
from spacebridgeapp.rest.util.utils import get_app_dict, validate_write_request

from spacebridgeapp.util.constants import SPACEBRIDGE_APP_NAME, AUTHTOKEN, SESSION, USER, APP_NAME, DISPLAY_APP_NAME, \
                                          PAYLOAD, STATUS

LOGGER = setup_logging(SPACEBRIDGE_APP_NAME + ".log", "rest_app_list")


class AppList(async_base_endpoint.AsyncBaseRestHandler):
    """
    Main class for handling the app_list endpoint. Subclasses the spacebridge_app
    BaseRestHandler.

    """

    async def get(self, request):
        """
        This method will process a DashboardAppListGetRequest.  This will return the list of app_names found under the
        dashboard_app_list key in the user_meta KVStore collection.

        :param request_context:
        :param client_single_request:
        :param single_server_response:
        :param async_client_factory:
        :return:
        """
        authtoken = request[SESSION][AUTHTOKEN]
        user = request[SESSION][USER]
        auth_header = SplunkAuthHeader(authtoken)
        request_context = RequestContext(auth_header, current_user=user, system_auth_header=auth_header)

        # async clients
        async_kvstore_client = self.async_client_factory.kvstore_client()
        async_splunk_client = self.async_client_factory.splunk_client()

        # Get dashboard_meta collection if key exists
        selected_apps = await fetch_dashboard_app_list_with_default(request_context=request_context,
                                                                    async_kvstore_client=async_kvstore_client,
                                                                    async_splunk_client=async_splunk_client)

        app_list = await fetch_app_names(request_context, async_splunk_client)
        app_dict = get_app_dict(app_list)
        # This filters out apps that are invalid from displaying in the app selection tab
        payload = [{APP_NAME: app, DISPLAY_APP_NAME: app_dict[app]} for app in selected_apps if app in app_dict]

        return {
            PAYLOAD: payload,
            STATUS: HTTPStatus.OK,
        }


    async def post(self, request):
        """
        Handler which creates a new app_list data entry in kvstore for the
        current user
        """
        authtoken = request[SESSION][AUTHTOKEN]
        user = request[SESSION][USER]
        auth_header = SplunkAuthHeader(authtoken)
        request_context = RequestContext(auth_header, current_user=user, system_auth_header=auth_header)

        async_splunk_client = self.async_client_factory.splunk_client()
        async_kvstore_client = self.async_client_factory.kvstore_client()

        total_app_list = await fetch_app_names(request_context, async_splunk_client)
        total_app_name_list = [app.app_name for app in total_app_list]

        selected_app_names = validate_write_request(request, total_app_list)
        # validate all app names
        for app_name in selected_app_names:
            if app_name not in total_app_name_list:
                error_message = f"The appName={app_name} is invalid.  Unable to set appName list."
                return {'error': error_message}

        # Store names in kvstore
        dashboard_app_list = await set_dashboard_app_list(request_context=request_context,
                                                          app_names=selected_app_names,
                                                          async_kvstore_client=async_kvstore_client,
                                                          async_splunk_client=async_splunk_client)
        return {
            PAYLOAD: dashboard_app_list.app_names,
            STATUS: HTTPStatus.OK,
        }

