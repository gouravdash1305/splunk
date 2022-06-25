"""
(C) 2020 Splunk Inc. All rights reserved.

Module to process Token Refresh Request
"""
import sys
from http import HTTPStatus

from spacebridgeapp.request.request_processor import JWTAuthHeader, async_is_valid_session_token
from spacebridgeapp.util import constants
from spacebridgeapp.logging import setup_logging
from cloudgateway.private.util.tokens_util import calculate_token_info
from cloudgateway.splunk.auth import SplunkJWTCredentials
from splapp_protocol import request_pb2


LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + "token_refresh_request_processor.log",
                       "token_refresh_request_processor")

async def process_token_refresh_request(request_context,
                                        client_single_request,
                                        server_single_response,
                                        async_splunk_client,
                                        encryption_context):

    if not isinstance(request_context.auth_header, JWTAuthHeader):
        secured_session_token = encryption_context.secure_session_token(request_context.auth_header.session_token)
        server_single_response.tokenRefreshResponse.sessionToken = secured_session_token
        server_single_response.tokenRefreshResponse.tokenExpiresAt = 0
        server_single_response.tokenRefreshResponse.code = request_pb2.TokenRefreshResponse.SUCCESS
        return

    session_token = request_context.auth_header.token
    valid_request = await async_is_valid_session_token(request_context.current_user, session_token, async_splunk_client)

    if not valid_request:
        server_single_response.tokenRefreshResponse.code = request_pb2.TokenRefreshResponse.ERROR_TOKEN_INVALID
        return

    old_token_info = calculate_token_info(session_token)
    new_JWT = await async_splunk_client.async_create_new_JWT_token(request_context.current_user, request_context.auth_header)
    if new_JWT.code not in {HTTPStatus.CREATED, HTTPStatus.OK}:
        error = await new_JWT.text()
        LOGGER.warning("Failed to create new token status_code={}, error={}".format(new_JWT.code, error))
        server_single_response.tokenRefreshResponse.code = request_pb2.TokenRefreshResponse.ERROR_CREATING_TOKEN
        return

    new_JWT_json = await new_JWT.json()
    new_jwt_credentials = SplunkJWTCredentials(request_context.current_user)
    new_jwt_credentials.token = new_JWT_json['entry'][0]['content']['token']

    # Get token expiry
    new_token_info = calculate_token_info(new_jwt_credentials.token)
    server_single_response.tokenRefreshResponse.tokenExpiresAt = new_token_info['exp']

    # Encrypt this token
    new_session_token = new_jwt_credentials.get_credentials() if sys.version_info < (3, 0) else str.encode(new_jwt_credentials.get_credentials())
    encrypted_token = encryption_context.secure_session_token(new_session_token)
    server_single_response.tokenRefreshResponse.sessionToken = encrypted_token
    server_single_response.tokenRefreshResponse.code = request_pb2.TokenRefreshResponse.SUCCESS
