# python imports
import os
import sys
import json
from typing import Optional, Union

# Reloading the rapid_diag bin path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

# splunk imports
import splunk
from splunk.persistconn.application import PersistentServerConnectionApplication
import splunklib.client as client

# local imports
import logger_manager as log
from rapid_diag_handler_utils import persistent_handler_wrap_handle, create_rapiddiag_payload, get_rest_search
from rapid_diag.task_handler import TaskHandler
from rapid_diag.util import get_server_name
from rapid_diag.serializable import JsonObject

_LOGGER = log.setup_logging("task_delete_endpoint")


class TaskDeleteEndpoint(PersistentServerConnectionApplication):
    """ Persisten REST endpoint responsible for task deletion.

        It takes one argument:
            task_id - ID of the task to be deleted.
    """
    def __init__(self, command_line : Optional[str] = None, command_arg : Optional[str] = None) -> None:
        pass

    def handle(self, args : Union[str, bytes]) -> JsonObject:
        """ Main handler body
        """
        return persistent_handler_wrap_handle(self._handle, args)

    def _handle(self, args : JsonObject) -> JsonObject:
        def delete_local(host_del : str) -> bool:
            for task in tasks:
                if task_id == task["task"]["task_id"] and host_del == task["task"]["host"]:
                    task_handler = TaskHandler()
                    task_handler.delete(json.dumps(task))
                    return True
            return False
        task_id = next((arg[1] for arg in args['query'] if arg[0]=='task_id'), '')
        local = next((arg[1] for arg in args['query'] if arg[0]=='local'), False)
        current_host = get_server_name(args['system_authtoken'])
        success = create_rapiddiag_payload(data="Started deleting the Task with ID: " + str(task_id) + ".")
        handler = TaskHandler()
        tasks = handler.list(current_host)

        if not local:
            if delete_local(current_host):
                return success
            return create_rapiddiag_payload(error='Task task_id="{}" not found.'.format(task_id))

        host = next((arg[1] for arg in args['query'] if arg[0]=='host'), 'local')
        service = client.connect(host=splunk.getDefault('host'),
                                port=splunk.getDefault('port'),
                                scheme=splunk.getDefault('protocol'),
                                token=args['system_authtoken'])
        kwargs_normalsearch = {"exec_mode": "normal"}
        rest_search = '| rest /services/rapid_diag/task_delete count=0 task_id="' + task_id + '"'
        params = 'task_id="' + task_id + '"'

        if host != current_host:
            rest_search = get_rest_search("rapid_diag/task_delete", host, params)
            delete_local(host)
        elif local:
            delete_local(host)

        service.jobs.create(rest_search, **kwargs_normalsearch)
        return success
