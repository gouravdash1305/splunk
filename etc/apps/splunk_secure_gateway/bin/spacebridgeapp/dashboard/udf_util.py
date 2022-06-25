"""Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved."""
import base64
from functools import partial
from enum import Enum
from http import HTTPStatus
from cloudgateway.private.encryption.encryption_handler import encrypt_for_send
from spacebridgeapp.exceptions.spacebridge_exceptions import SpacebridgeApiRequestError
from spacebridgeapp.util.constants import UDF_IMAGE_RESOURCE_COLLECTION, UDF_ICON_RESOURCE_COLLECTION

HOSTED_KVSTORE_PREFIX = "splunk-enterprise-kvstore://"
ICON_VISUALIZATION_TYPE = "icon"
IMAGE_VISUALIZATION_TYPE = "image"


class HostedResourceType(Enum):
    """
    Enum to enumerate different types of hosted resources such as whether the resource is hosted in kv store
    """

    UNKNOWN = 0
    URL = 1
    KVSTORE = 2


def parse_hosted_resource_path(resource_path):
    """

    Given a resource path string, parse the string to return the type of the resource and return a tuple of the
    resource type and the parsed resource path
    :param resource_path:
    :return: (HostedResourceType, Resource Path String)
    """

    resource_path = resource_path.strip()
    if resource_path.startswith(HOSTED_KVSTORE_PREFIX):
        return HostedResourceType.KVSTORE, resource_path[len(HOSTED_KVSTORE_PREFIX):]
    elif resource_path.startswith("http://") or resource_path.startswith("https://"):
        return HostedResourceType.URL, resource_path
    else:
        return HostedResourceType.UNKNOWN, resource_path


def parse_udf_kvstore_resource(data_jsn, request_context=None):
    """
    Parse the response from KV Store for stored resources
    :param data_jsn:
    :param request_context:
    :return: (String, Bytes) containing the mime-type of the resource and the raw bytes of the resource respectively
    """
    data_uri = data_jsn["dataURI"]
    d = data_uri.split(",")
    data_meta = d[0]
    data_payload = d[1]
    mime, encoding = data_meta.split(";")

    if encoding != 'base64':
        raise SpacebridgeApiRequestError(
            "Unexpected data encoding type. Expected base64 but got {}, {}".format("base64", request_context),
            status_code=HTTPStatus.BAD_REQUEST)

    resource_bytes = base64.b64decode(data_payload)
    return mime, resource_bytes


def build_encrypted_resource(data_json, device_encrypt_public_key, encryption_context, request_context):
    """
    Takes the response from KV Store for a stored resource and returns a tuple containing the MIME type of the
    resource and the encrypted bytes of the resource encrypted with the client device's public key
    :param data_json:
    :param device_encrypt_public_key:
    :param encryption_context:
    :param request_context:
    :return: (String, Bytes)
    """
    mime, resource_bytes = parse_udf_kvstore_resource(data_json, request_context)

    encryptor = partial(encrypt_for_send, encryption_context.sodium_client,
                        device_encrypt_public_key)

    return mime, encryptor(resource_bytes)


def get_collection_from_resource_type(resource_type):
    """
    Give a resource type for a KV Store Collection Resource, map it to the corresponding KV Store collection.
    This is needed because images and icons are stored in separate KV store collections.
    :param resource_type: String
    :return: KV Store Collection name (String)
    """
    if resource_type.lower() == ICON_VISUALIZATION_TYPE:
        return UDF_ICON_RESOURCE_COLLECTION

    return UDF_IMAGE_RESOURCE_COLLECTION





