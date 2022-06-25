"""Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved."""
from cloudgateway.private.encryption.encryption_handler import sign_detached
from http import HTTPStatus
from spacebridge_protocol import http_pb2
from spacebridgeapp.dashboard.udf_util import parse_hosted_resource_path, HostedResourceType, \
    build_encrypted_resource, get_collection_from_resource_type
from spacebridgeapp.exceptions.spacebridge_exceptions import SpacebridgeApiRequestError
from spacebridgeapp.util import constants
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.messages.util import fetch_device_info
from spacebridgeapp.request.request_processor import SpacebridgeAuthHeader

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + "_udf_request_processor", "udf_request_processor")


async def process_udf_hosted_resource_get(request_context,
                                          client_single_request,
                                          server_single_response,
                                          async_kvstore_client=None,
                                          async_spacebridge_client=None,
                                          encryption_context=None):
    """
    Process a UDF hosted resource get request. This used for fetching assets which are used within UDF dashboards
    such as images.
    :param request_context:
    :param client_single_request:
    :param server_single_response:
    :param async_kvstore_client:
    :param async_spacebridge_client:
    :param encryption_context:
    :return: None
    """
    resourcePath = client_single_request.udfHostedResourceRequest.resourceUrl
    resource_type, parsed_path = parse_hosted_resource_path(resourcePath)

    if resource_type == HostedResourceType.KVSTORE:

        collection = get_collection_from_resource_type(client_single_request.udfHostedResourceRequest.resourceType)

        r = await async_kvstore_client.async_kvstore_get_request(collection,
                                                                 request_context.system_auth_header,
                                                                 key_id=parsed_path,
                                                                 app=constants.SPLUNK_DASHBOARD_APP)
        if r.code != HTTPStatus.OK:
            response = await r.text()
            raise SpacebridgeApiRequestError(
                "Exception fetching resource from KV Store with error_code={}, error_msg={}".format(r.code, response),
                status_code=r.code)

        response = await r.json()
        device_info = await fetch_device_info(request_context.raw_device_id, async_kvstore_client,
                                              request_context.system_auth_header)

        mime, payload = build_encrypted_resource(response, device_info.encrypt_public_key, encryption_context,
                                                 request_context)
        signature = sign_detached(encryption_context.sodium_client, encryption_context.sign_private_key(), payload)
        sender_id = encryption_context.sign_public_key(transform=encryption_context.generichash_raw)

        r = await async_spacebridge_client.async_send_storage_request(payload, mime, signature,
                                                                      SpacebridgeAuthHeader(sender_id),
                                                                      request_context.request_id)
        response = await r.content()
        storage_response = http_pb2.StorageResponse()
        storage_response.ParseFromString(response)

        if r.code != HTTPStatus.OK:
            raise SpacebridgeApiRequestError("Exception storing resource to cloudgateway with code={}, error_msg={}"
                                             .format(r.code, storage_response), status_code=r.code)

        server_single_response.udfHostedResourceResponse.encryptedResourceUrl = storage_response.payload.readUri

    elif resource_type == HostedResourceType.URL:
        raise SpacebridgeApiRequestError("Fetching URLs resource from cloudgateway is not currently supported",
                                         status_code=HTTPStatus.METHOD_NOT_ALLOWED)
    else:
        raise SpacebridgeApiRequestError("Exception fetching hosted resource, unknown resource type",
                                         status_code=HTTPStatus.BAD_REQUEST)
