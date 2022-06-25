# pylint: disable=missing-function-docstring,missing-class-docstring
# python imports
import os
import sys
import json
import time
from typing import Optional, Union

# Reloading the rapid_diag bin path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

# splunk imports
import splunk
from splunk.persistconn.application import PersistentServerConnectionApplication
import splunklib.client as client
from splunklib.six.moves.urllib import parse

# local imports
import logger_manager as log
from rapid_diag_handler_utils import persistent_handler_wrap_handle, create_rapiddiag_payload
from rapid_diag.task_handler import TaskHandler
from rapid_diag.util import get_server_name
from rapid_diag.serializable import JsonObject

_LOGGER = log.setup_logging("task_run_endpoint")


class TaskRunEndpoint(PersistentServerConnectionApplication):
    def __init__(self, command_line : Optional[str] = None, command_arg : Optional[str] = None):
        pass

    def handle(self, args : Union[str, bytes]) -> JsonObject:
        return persistent_handler_wrap_handle(self._handle, args)

    def _handle(self, args : JsonObject) -> JsonObject: # pylint: disable=too-many-locals
        task_body_string = None
        peers_string = None
        try:
            task_body_string = next((arg[1] for arg in args['query'] if arg[0]=='payload'), '')
            peers_string = next((arg[1] for arg in args['query'] if arg[0]=='peers'), '[]')
            peers = json.loads(peers_string)
            task_body = json.loads(parse.unquote(task_body_string))
            task_name = task_body.get('name', '')
            success = create_rapiddiag_payload(data="Task " + task_name + " has started.")
        except Exception as exc: # pylint: disable=broad-except
            _LOGGER.exception("Aborting: JSON decode error. Invalid JSON format or request body not found.",
                              exc_info=exc)
            return create_rapiddiag_payload(error="JSON decode error. Invalid JSON format or request body not found.")

        try:
            host = get_server_name(args['system_authtoken'])
            if not peers:
                if not task_body.get("host"):
                    task_body["host"] = host
                task_id = next((arg[1] for arg in args['query'] if arg[0]=='task_id'),
                               TaskHandler.build_task_id(task_name, task_body["host"]))
                task_body.update({'task_id': task_id})
                task_body = json.dumps(task_body)
                task_handler = TaskHandler()
                task = task_handler.create(task_body)
                run_info = None
                if task is not None:
                    run_info = task_handler.run_detached(task, args['system_authtoken'])
                if run_info is None:
                    return create_rapiddiag_payload(error="Unable to start task collection process.")
            else:
                task_id = TaskHandler.build_task_id(task_name, host)
                task_body = json.dumps(task_body)

                service = client.connect(host=splunk.getDefault('host'),
                                         port=splunk.getDefault('port'),
                                         scheme=splunk.getDefault('protocol'),
                                         token=args['system_authtoken'])
                kwargs_normalsearch = {"exec_mode": "normal"}
                jobs = []
                for peer in peers:
                    rest_search = '| rest /services/rapid_diag/task_runner count=0 splunk_server="' +\
                                    peer + '" payload="' + task_body_string + '" task_id="' + task_id + '"'
                    job = service.jobs.create(rest_search, **kwargs_normalsearch)
                    jobs.append(job)
                for job in jobs:
                    while not job.is_done():
                        time.sleep(0.1)
            return success
        except Exception as e: # pylint: disable=broad-except
            _LOGGER.exception("Error decoupling data collection process: %s", str(e), exc_info=e)
        return create_rapiddiag_payload(error="Error starting up task collection process.")
