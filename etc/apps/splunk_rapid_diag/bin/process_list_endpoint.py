# python imports
import os
import sys
import json
from typing import Optional, Union

# Reloading the rapid_diag bin path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication

# local imports
import logger_manager as log
from rapid_diag_handler_utils import get_endpoint
from rapid_diag_handler_utils import persistent_handler_wrap_handle
from rapid_diag_handler_utils import create_rapiddiag_payload
from rapid_diag.serializable import JsonObject
from rapid_diag.util import get_server_name
from rapid_diag.session_globals import SessionGlobals

_LOGGER = log.setup_logging("process_list_endpoint")


class ProcessListEndpoint(PersistentServerConnectionApplication):
    """ Persisten REST endpoint responsible for providing a list
        of processes running on the server.
    """
    def __init__(self, command_line : Optional[str] = None, command_arg : Optional[str] = None):
        pass

    def handle(self, args : Union[str, bytes]) -> JsonObject:
        """ Main handler body
        """
        def _handle(args : JsonObject) -> JsonObject:
            peers_string = next((arg[1] for arg in args['query'] if arg[0] == 'peers'), '[]')
            peers = json.loads(peers_string)
            if not peers:
                proc_data = SessionGlobals.get_process_lister().get_ui_process_list()
            else:
                if len(peers) > 1 and peers[0] == get_server_name(args['system_authtoken']):
                    peers = peers[1:]
                peer_data = get_endpoint('rapid_diag/get_process_info', args['system_authtoken'], peers[0])
                proc_data = json.loads(peer_data[0].get('value')) # type: ignore
            _LOGGER.debug("Process Data: %s", str(proc_data))
            return create_rapiddiag_payload(data=proc_data)
        return persistent_handler_wrap_handle(_handle, args)
