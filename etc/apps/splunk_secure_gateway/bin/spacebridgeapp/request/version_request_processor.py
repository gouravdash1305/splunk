"""Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved."""
from spacebridgeapp.data.telemetry_data import InstallationEnvironment
from http import HTTPStatus
from spacebridgeapp.request.generic_request_processor import fetch_registered_apps
from spacebridgeapp.rest.clients.async_client_factory import AsyncClientFactory
from spacebridgeapp.util import constants
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util.constants import VERSION
from spacebridgeapp.versioning import app_version, minimum_build
from splapp_protocol import request_pb2

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + "_version_request_processor", "version_request_processor")


async def process_get_version_request(request_context,
                                      client_single_request,
                                      server_single_response,
                                      async_client_factory: AsyncClientFactory):
    """
    Process getVersionRequest by returning splunk app version number, min supported client version and friendly name
    for device
    :param request_context:
    :param client_single_request:
    :param server_single_response:
    :param async_client_factory:
    :return:
    """
    LOGGER.debug("Processing get version")

    async_kvstore_client = async_client_factory.kvstore_client()
    async_telemetry_client = async_client_factory.telemetry_client()
    async_splunk_client = async_client_factory.splunk_client()

    server_single_response.versionGetResponse.SetInParent()
    server_single_response.versionGetResponse.cloudgatewayAppVersion = str(app_version())

    user_agent = request_context.user_agent or "invalid"
    agent_parts = user_agent.split('|')
    app_id = agent_parts[0]

    app_min_build = minimum_build(app_id)
    server_single_response.versionGetResponse.minimumClientVersion = str(app_min_build)

    auth_header = request_context.auth_header

    companion_app_list = await fetch_registered_apps(auth_header, async_splunk_client)
    for key, app in companion_app_list.items():
        companion = server_single_response.versionGetResponse.companionApps.add()
        companion.appId = key
        companion.appVersion = app[VERSION]

    device_name = await _get_device_name(auth_header, auth_header.username, request_context.device_id,
                                         async_kvstore_client, request_context)

    server_single_response.versionGetResponse.deviceName = device_name

    deployment_friendly_name = await _get_deployment_friendly_name(auth_header, async_kvstore_client, request_context)
    server_single_response.versionGetResponse.deploymentFriendlyName = deployment_friendly_name

    telemetry_instance_id = await async_telemetry_client.get_telemetry_instance_id(auth_header)
    server_single_response.versionGetResponse.instanceId = telemetry_instance_id

    installation_environment = await async_telemetry_client.get_installation_environment(auth_header)
    installation_environment_proto = request_pb2.VersionGetResponse.CLOUD \
        if installation_environment is InstallationEnvironment.CLOUD \
        else request_pb2.VersionGetResponse.ENTERPRISE
    server_single_response.versionGetResponse.installationEnvironment = installation_environment_proto

    splunk_version = await async_telemetry_client.get_splunk_version(auth_header)
    server_single_response.versionGetResponse.splunkVersion = splunk_version

    LOGGER.debug("Finished processing get version")


async def _get_device_name(auth_header, user, device_id, async_kvstore_client, request_context):
    """
    Get friendly name for device given it's device id
    :param auth_header:
    :param user:
    :param device_id:
    :param async_kvstore_client:
    :return:
    """

    response = await async_kvstore_client.async_kvstore_get_request(
        constants.REGISTERED_DEVICES_COLLECTION_NAME, auth_header=auth_header, owner=user)

    if response.code == HTTPStatus.OK:
        response_json = await response.json()

        for device in response_json:
            if device["device_id"] == device_id:
                return device["device_name"]

    LOGGER.error("Unable to fetch friendly name for device={}, code={}".format(device_id, response.code))
    return ""

async def _get_deployment_friendly_name(auth_header, async_kvstore_client, request_context):
    """
    Get friendly name for deployment
    :param auth_header:
    :param async_kvstore_client:
    :return:
    """

    response = await async_kvstore_client.async_kvstore_get_request(
        constants.META_COLLECTION_NAME, auth_header=auth_header, owner=constants.NOBODY)

    if response.code == HTTPStatus.OK:
        response_json = await response.json()
        return response_json[0][constants.DEPLOYMENT_FRIENDLY_NAME]

    LOGGER.error("Unable to fetch deployment friendly name for instance, code={}".format(response.code))
    return ""

