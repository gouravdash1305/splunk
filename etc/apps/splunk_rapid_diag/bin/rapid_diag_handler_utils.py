# pylint: disable=missing-function-docstring,missing-class-docstring
# python imports
import json
from typing import List, Optional, Callable, Union

# splunk imports
import splunk

import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError
import logger_manager as log
from rapid_diag.session_globals import SessionGlobals

# local imports
from rapid_diag.serializable import JsonObject, Serializable
from rapid_diag.util import get_server_name
from rapid_diag.debug_utils import Profiler # pylint: disable-msg=E0611
# below is needed to register signal handler
import rapid_diag.trace # pylint: disable=unused-import

API_VERSION = 1

_LOGGER = log.setup_logging("rapid_diag_handler_utils")

def get_endpoint(endpoint : str,
                 session_key : str,
                 peer : Optional[str] = None,
                 filter_errors : bool = True) -> List[JsonObject]:
    service = client.connect(host=splunk.getDefault('host'),
                             port=splunk.getDefault('port'),
                             scheme=splunk.getDefault('protocol'),
                             token=session_key)

    rest_search = get_rest_search(endpoint, peer)

    # we only ignore errors from RD endpoints
    if filter_errors:
        rest_search += ' | eval error=json_extract(value, "error") | search NOT error=*'

    data = service.jobs.oneshot(rest_search)
    reader = results.ResultsReader(data)

    def _handle_info() -> List[JsonObject]:
        data : List[JsonObject] = []
        current_host = get_server_name(session_key)
        for item in reader:
            # always keeping originating SH value first
            idx = 0 if item.get("splunk_server","") == current_host else len(data)
            data.insert(idx, {"value": item.get("value", {}), "splunk_server": item.get("splunk_server","")})
        return data

    if endpoint.startswith("rapid_diag"):
        return _handle_info()
    # pylint: disable=not-callable
    return reader.next().get('value') # type: ignore
    # pylint: enable=not-callable


def create_rapiddiag_payload(data : Optional[Union[JsonObject, List[JsonObject], List[Serializable], str]] = None,
        error : Optional[str] = None,
        status : int = 200) -> JsonObject:
    """ Create payload returned by REST handlers.
        By default we return status 200 and an empty payload.
        If error is provided - data is not appended to the payload.
    """
    str_payload : str = "{}"
    # To avoid handling weird edge cases - drop data if error is provided
    if error:
        str_payload = json.dumps({ 'error' : error })
    elif data:
        # if we were provided with a string - add 'message' field
        if isinstance(data, str):
            str_payload = json.dumps({'message' : data})
        else:
        # otherwise - we assume it's a ready payload - so just use it
            str_payload = json.dumps(data)

    return {'payload': str_payload,
            'status': status,
            'headers': {
                'Content-Type': 'text/plain' # for now we use text content type for all payloads
                }
            }

def get_rest_search(endpoint: str, peer : Optional[str] = None, params : str = '') -> str:
    rest_search = '| rest /services/' + endpoint + ' count=0 max_api_version=' + str(API_VERSION)  + ' ' + params
    if peer:
        rest_search += ' splunk_server="' + peer + '"'
    else:
        rest_search += ' splunk_server=*'
    return rest_search

def persistent_handler_wrap_handle(handler : Callable[[JsonObject], JsonObject], # pylint: disable=too-many-return-statements
                    args : Union[str, bytes],
                    supported_methods : Optional[List[str]] = None) -> JsonObject:

    if supported_methods is None:
        supported_methods=['GET']

    with Profiler(_LOGGER) as prof: # pylint: disable=unused-variable
        args_json : JsonObject = {}
        try:
            SessionGlobals.reset()
            args_json = json.loads(args)
        except Exception as e: # pylint: disable=broad-except
            _LOGGER.exception("Payload must be a json parseable string, JSON Object, or JSON List: %s : %s",
                              str(args), str(e), exc_info=e)
            return create_rapiddiag_payload(error="Invalid request data: " + str(args) + "; exception=" + str(e))
        if args_json.get('method') not in supported_methods:
            _LOGGER.error("Request method must be in %s : %s", str(supported_methods), str(args))
            return create_rapiddiag_payload(error="Method Not Allowed: Request method must be in " +
                                            str(supported_methods), status=405)
        max_api_version = next((arg[1] for arg in args_json['query'] if arg[0] == 'max_api_version'), API_VERSION)
        if int(max_api_version) < API_VERSION:
            return create_rapiddiag_payload(error="Unable to provide results for max_api_version=" +
                                            str(max_api_version) + ", my_api_version=" +
                                            str(API_VERSION) + " is higher.")

        def build_error_message(description : str, details : str) -> str:
            return description + str(args_json['rest_path']) + ': ' + details

        try:
            return handler(args_json)
        except SyntaxError as e:
            _LOGGER.exception("Syntax error: %s", str(e), exc_info=e)
            return create_rapiddiag_payload(error="You've found a bug! Very embarrassing, " +
                                            "we're deeply sorry and would appreciate it if you " +
                                            "could report it back to Support: " + str(e))
        except splunk.RESTException as e:
            msg = build_error_message('REST Error processing request to ', e.msg)
            _LOGGER.exception(msg, exc_info=e)
            return create_rapiddiag_payload(error=msg, status=e.statusCode)
        except HTTPError as e:
            msg = build_error_message('HTTP Error processing request to ', e.reason)
            _LOGGER.exception(msg, exc_info=e)
            return create_rapiddiag_payload(error=msg, status=e.status)
        except Exception as e: # pylint: disable=broad-except
            msg = build_error_message('Error processing request to ', str(e))
            _LOGGER.exception(msg, exc_info=e)
            return create_rapiddiag_payload(error=msg)
