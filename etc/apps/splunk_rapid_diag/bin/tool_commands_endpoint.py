# python imports
import os
import sys
import json
from typing import Optional, Union, Dict, Type, Tuple, Any, Iterator, List

# Reloading the rapid_diag bin path
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication

# local imports
import logger_manager as log
from rapid_diag_handler_utils import persistent_handler_wrap_handle
from rapid_diag_handler_utils import create_rapiddiag_payload
from rapid_diag.serializable import JsonObject
from rapid_diag.collector.tools_collector import ToolsCollector
from rapid_diag.serializable import Serializable

_LOGGER = log.setup_logging("tool_commands_endpoint")

class ToolCommandsEndpoint(PersistentServerConnectionApplication):
    """ Persisten REST endpoint responsible for providing a command list for the tools
    """
    def __init__(self, command_line: Optional[str] = None, command_arg: Optional[str] = None):
        pass

    def handle(self, args: Union[str, bytes]) -> JsonObject:
        """ Main handler body
        """

        def _handle(args: JsonObject) -> JsonObject:
            collectors_string = next((arg[1] for arg in args['query'] if arg[0] == 'collectors'), '[]')
            collectors = json.loads(collectors_string)
            try:
                commands_data = self.get_commands_for_collectors(collectors)
            except ValueError as val_error:
                return create_rapiddiag_payload(error="Cannot get tool argument due to error {}".format(val_error), status=404)
            return create_rapiddiag_payload(data=commands_data)

        return persistent_handler_wrap_handle(_handle, args)

    def get_collectors_class_map(self)-> Dict[str, Type[ToolsCollector]]:
        """collectors class map to get tools collectors"""
        collector_class_map = dict()
        for k, val in Serializable.classes.items():
            if issubclass(val, ToolsCollector):
                collector_class_map[val.__module__.rsplit('.', 1)[1]] =  Serializable.classes[k]
        return collector_class_map

    def deepest_pairs(self, arg_dictionary: Dict[str, Any]) -> Iterator[Tuple[str, Any]]:
        """do deep dive in to the args dictionary to get all nested dicts"""
        for key, value in arg_dictionary.items():
            if isinstance(value, dict):
                yield (key, value)
                yield from self.deepest_pairs(value)
            else:
                yield (key, value)

    def get_commands_for_collectors(self, collectors: List[JsonObject]) -> Dict[str, str]:
        """ get the command that will be used by the collector tool"""
        collector_class_map = self.get_collectors_class_map()
        all_commands = dict()
        for collector in collectors:
            for key, val in collector.items():
                if "args" not in val:
                    raise ValueError('No args provided for tool "{}"'.format(key))
                if key in collector_class_map:
                    arg_keys = collector_class_map[key].get_tool_arguments()
                    all_args= {k:v for k, v in self.deepest_pairs(val["args"]) if k in arg_keys}
                    if not frozenset(all_args.keys()) <= collector_class_map[key].get_tool_arguments():
                        raise ValueError('Not all args provided for tool "{}" args needed {} '.format(key, ' '.join(arg_keys)))
                    tool_command = collector_class_map[key].get_tool_command(**all_args)
                    all_commands[key] = '' if (None in tool_command) else ' '.join(tool_command)
        return all_commands
