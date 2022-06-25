"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.

REST endpoint handler for restarting SSG modular inputs
"""

import sys
import json
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'splunk_secure_gateway', 'bin']))

from http import HTTPStatus
from spacebridgeapp.util import py23
from spacebridgeapp.logging import setup_logging
from spacebridgeapp.util import constants
from spacebridgeapp.rest.base_endpoint import BaseRestHandler
from spacebridgeapp.rest.services import splunk_service

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + ".log", "restart_ssg")

class RestartSsgInputs(BaseRestHandler, PersistentServerConnectionApplication):

    def __init__(self, command_line, command_arg):
        BaseRestHandler.__init__(self)

    def get(self, request):
        """
        Restart modular inputs associated to SSG
        """
        LOGGER.info("Received request to restart SSG modular inputs")
        user_token = request['session']['authtoken']
        return _restart_inputs(user_token)


def _restart_inputs(user_authtoken):
    inputs = splunk_service.get_ssg_mod_inputs(user_authtoken)
    LOGGER.info("Restarting modular_inputs=%s", inputs)
    responses = {}

    for input in inputs:
        r = splunk_service.toggle_ssg_input(input, user_authtoken)
        responses[input] = r.status

    LOGGER.info("Completed restart of inputs with responses=%s", responses)
    return {
        'status': 200,
        'payload': responses
    }

