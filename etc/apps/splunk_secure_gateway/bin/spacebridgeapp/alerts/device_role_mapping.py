"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

Module which handles updating the device role mapping kvstore table
"""

import asyncio
import json
import sys
import os
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'lib']))
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
from http import HTTPStatus
from spacebridgeapp.request.splunk_auth_header import SplunkAuthHeader
from spacebridgeapp.util import constants
from spacebridgeapp.util.time_utils import get_current_timestamp

from spacebridgeapp.logging import setup_logging

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + '_modular_input.log', 'device_role_mapping.app')


async def update(session_token, async_kvstore_client, async_splunk_client):
    """
    Update the devices to role mapping collection in KV Store
    """
    timestamp = get_current_timestamp()
    splunk_auth_header = SplunkAuthHeader(session_token)

    # for each user, fetch user to roles mapping
    response_code, user_to_role_dict = await async_splunk_client.async_get_users_roles_mapping(splunk_auth_header)

    LOGGER.debug("Fetched user role mapping with response code=%s, %s" % (str(response_code), str(user_to_role_dict)))

    # For each user fetch devices registered to that user
    registered_devices_jsn = await get_registered_devices(splunk_auth_header, list(user_to_role_dict.keys()),
                                                          async_kvstore_client)

    # Construct kvstore payload
    batch_payload = create_payloads(registered_devices_jsn, user_to_role_dict, timestamp)
    batch_post_to_kvstore(session_token, batch_payload)
    await clean_up_old_entries(timestamp, async_kvstore_client, session_token)


async def clean_up_old_entries(timestamp, async_kvstore_client, session_token):
    """
    Delete entries in the devices to roles mapping collection older than input timestamp
    """
    try:
        query = {constants.OR_OPERATOR:
            [
                {constants.TIMESTAMP: {constants.LESS_THAN_OPERATOR: timestamp}},
                {constants.TIMESTAMP: {constants.GREATER_THAN_OPERATOR: timestamp}}
            ]
        }
        params = {constants.QUERY: json.dumps(query)}
        r = await async_kvstore_client.async_kvstore_delete_request(collection=constants.DEVICE_ROLES_COLLECTION_NAME,
                                                                    auth_header=SplunkAuthHeader(session_token),
                                                                    params=params)
        LOGGER.debug("finished deleting old entry with code=%s" % str(r.code))
    except:
        LOGGER.exception("exception deleting old entries")


async def get_registered_devices(auth_header, user_list, async_kvstore_client, max_batch_size=20):
    """
    fetch list of devices for a list of users
    """
    devices_table = constants.REGISTERED_DEVICES_COLLECTION_NAME
    n = len(user_list)

    try:
        registered_devices = []

        for idx in range(0, n, max_batch_size):
            # Boundary condition
            end_idx = min(n, idx + max_batch_size)

            # Make max_batch_size requests concurrently and wait for them to complete
            responses = await asyncio.gather(*[async_kvstore_client.async_kvstore_get_request(
                devices_table, owner=user, auth_header=auth_header) for user in user_list[idx: end_idx]],
                                             return_exceptions=True)

            responses = await asyncio.gather(*[r.json() for r in responses if not isinstance(r, Exception) and
                                               r.code == HTTPStatus.OK])

            exceptions = [e for e in responses if isinstance(e, Exception)]

            if exceptions:
                LOGGER.exception("Encountered exceptions fetching some registered devices, e=%s", str(exceptions))

            registered_devices.append(
                [device
                 for response in responses for device in response
                 if device.get(constants.REGISTERED_DEVICES_DEVICE_TYPE, None) == constants.ALERTS_IOS])

            return [device for user_devices in registered_devices for device in user_devices]

    except Exception:
        LOGGER.exception("Exception getting registered_devices")
        return []


def create_payloads(registered_devices, user_to_role_mapping, timestamp):
    """
    Given a list of devices and a mapping of user to roles, create the payload to be inserted in KV Store
    """
    payload = []

    for device in registered_devices:
        user = device[constants.USER_KEY]
        if user not in user_to_role_mapping.keys():
            continue

        for role in user_to_role_mapping[user]:
            payload.append({
                constants.ROLE: role,
                constants.REGISTERED_DEVICES_DEVICE_ID: device[constants.REGISTERED_DEVICES_DEVICE_ID],
                constants.TIMESTAMP: timestamp
            })

    return payload


def batch_post_to_kvstore(session_token, payload):
    try:
        from spacebridgeapp.util.kvstore import KVStoreBatchWriter
        KvBatchStorer = KVStoreBatchWriter(namespace=constants.SPACEBRIDGE_APP_NAME,
                                           collection=constants.DEVICE_ROLES_COLLECTION_NAME)
        r = KvBatchStorer.batch_save(session_token, constants.NOBODY, payload)
        LOGGER.debug("batch storer num_stored=%s" % str(len(r)))
    except:
        LOGGER.exception("Exception during batch upload of role to device mapping")
