# pylint: disable=missing-function-docstring,missing-class-docstring
# python imports
import os
import sys
import json
from typing import Optional, Union, List

# Reloading the rapid_diag bin path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication

# local imports
import logger_manager as log
from rapid_diag_handler_utils import get_endpoint, persistent_handler_wrap_handle, create_rapiddiag_payload
from rapid_diag.serializable import JsonObject
from rapid_diag.util import get_log_files

_LOGGER = log.setup_logging("log_file_list_endpoint")


class LogFileListEndpoint(PersistentServerConnectionApplication):
    def __init__(self, command_line : Optional[str] = None, command_arg : Optional[str] = None):
        pass

    def handle(self, args : Union[str, bytes]) -> JsonObject:
        return persistent_handler_wrap_handle(self._handle, args)

    def _handle(self, args : JsonObject) -> JsonObject:
        peers_string = next((arg[1] for arg in args['query'] if arg[0] == 'peers'), '[]')
        peers = json.loads(peers_string)
        log_files : List[str] = []
        if not peers:
            log_files = get_log_files()
        else:
            endpoint_data  : List[JsonObject] = get_endpoint('rapid_diag/get_log_files', args['system_authtoken'])
            log_files_set = set()
            for result in endpoint_data:
                if result.get('splunk_server') not in peers:
                    continue
                log_files_set.update(json.loads(result.get('value')).values()) # type: ignore
            log_files = list(log_files_set)
        _LOGGER.debug("List of log files: %s", str(log_files))
        log_files_payload = {str(idx): val for idx, val in enumerate(sorted(log_files))} # pylint: disable=unnecessary-comprehension
        return create_rapiddiag_payload(data=log_files_payload)
