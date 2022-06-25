import requests
import json
from urllib.parse import quote
from commonAuth import *
# This is for getting SAML user information, it is an alternative to using SAML attribute
# query requests (AQR) which Okta does not support.
#
# Provide Okta API key credentials and base url in the authentication.conf
# file or using the Splunk Web UI
# (Settings > Authentication Methods > SAML Configuration > Authentication Extensions)
# and use the Okta API to extract user information.
#
# In authentication.conf, configure the 'scriptSecureArguments' setting to
# "apiKey:<your Okta API key>" and "baseUrl:<your Okta url>. For example:
#
# scriptSecureArguments = apiKey:<your Okta API key string>,baseUrl:<your Okta url>
#
# After you restart the Splunk platform, the platform encrypts your Okta credentials.
# For more information about Splunk platform configuration files, search the
# Splunk documentation for "about configuration files".
#
# In Splunk Web UI under Authentication Extensions > Script Secure Arguments:
# key = apiKey, value = <your Okta API key string>
# key = baseUrl, value =<your Okta url>
request_timeout = 10
def getUserInfo(args):
    logger = getLogger("{}/splunk_scripted_authentication_okta.log".format(logPath), "okta")
    username = args['username']

    if not username:
        logger.error("Username is empty. Not executing API call")
        return FAILED

    # Extracting base url and API key from authentication.conf under scriptSecureArguments
    BASE_URL = args['baseUrl']
    API_KEY = args['apiKey']
    API_KEY_HEADER = 'SSWS ' + API_KEY
    OKTA_HEADERS = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': API_KEY_HEADER}
    OKTA_USER_SEARCH_INPUT = "oktaUserSearch"
    encoded_username = quote(username)
    if OKTA_USER_SEARCH_INPUT not in args:
        # By default use the email as the attribute to query user information from Okta.
        # Typically Okta APIs can be quieried directly using the email attribute.
        # For example, for a customer Acme and username "acme@example.com" the Okta
        # URL will look something like
        # https://acme.okta.com/api/v1/users/<Base64UrlEncode(acme@example.com)>
        usernameUrl = BASE_URL + '/api/v1/users/' + encoded_username
        groupsUrl = usernameUrl + '/groups'
        usernameResponse = requests.request('GET', usernameUrl, headers=OKTA_HEADERS, timeout=request_timeout)
        groupsResponse = requests.request('GET', groupsUrl, headers=OKTA_HEADERS, timeout=request_timeout)
        try:
            nameAttributes = json.loads(usernameResponse.text)
        except Exception as e:
            logger.error("Failed to parse user info for username={} with error={}".format(username, str(e)))
            return FAILED
        if 'status' not in nameAttributes:
            logger.error("Failed to parse user info for username={}, status not present in response output".format(username))
            return FAILED
        status = nameAttributes['status']
    else:
        # In rare cases (like when Okta has been paired with a customer's Active Directory) the email may *not*
        # used directly to lookup user information. In such cases an AD attribute e.g (sAMAccountName) is needed.
        # More info https://help.okta.com/en/prod/Content/Topics/Directory/Directory_AD_Field_Mappings.htm
        # In such cases we allow the customer to construct a search based on whatever attribute they have choosen.
        # Okta's user APIs are queried by construncting a search with the unique user identifier passed in as a
        # argument to the script. This can be done directly through the SAML configuration page or
        # through authentication.conf
        # if the user has passed in a custom search attribute, use that instead of the email.
        # API Ref: https://developer.okta.com/docs/reference/api/users/#list-users-with-search
        # Note that this search attribute is passed in as a key:value pair through the scripted inputs section.
        # E.g if  we want to search based on 'samAccountName' we will pass in the following input to the script
        #
        # search=profile.samAccountName eq <attr-to-be-queried>
        #
        # Currently, only one attribute is allowed as an input to search.
        # https://acme.okta.com/api/v1/users/?<Base64UrlEncode(search profile.samAccountName eq <username>)>
        logger.info('Using attribute={} to do a lookup for value={}'.format(args[OKTA_USER_SEARCH_INPUT], encoded_username))
        query = '{} eq \"{}\"'.format(args[OKTA_USER_SEARCH_INPUT], username)
        searchUrl = '/api/v1/users/?search=' + quote(query)
        usernameUrl = BASE_URL + searchUrl
        logger.info("Okta search url is {}".format(usernameUrl))
        usernameResponse = requests.request('GET', usernameUrl, headers=OKTA_HEADERS, timeout=request_timeout)
        if usernameResponse.status_code != 200:
            logger.error("Failed to get user info for username={} with user response status={} and user "
                         "response={}".format(username, usernameResponse.status_code, usernameResponse.text))
            return FAILED
        try:
            nameAttributes = json.loads(usernameResponse.text)
        except Exception as e:
            logger.error("Failed to parse user info for username={} with error={}".format(username, str(e)))
            return FAILED
        if not len(nameAttributes):
            logger.error("Search query returned an empty response using attribute={} to do a lookup for value={}".format(args[OKTA_USER_SEARCH_INPUT], encoded_username))
            return FAILED
        if len(nameAttributes) > 1:
            logger.error("Returned  more than one result while fetching get user info for username={} with user response status={} and user response={}. Check your search criteria.".format(username, usernameResponse.status_code, usernameResponse.text))
            return FAILED
        loginNameString = nameAttributes[0]['profile']['email']
        groupsUrl = BASE_URL + '/api/v1/users/' + loginNameString + '/groups'
        groupsResponse = requests.request('GET', groupsUrl, headers=OKTA_HEADERS, timeout=request_timeout)
        try:
            nameAttributes = json.loads(usernameResponse.text)[0]
        except Exception as e:
            logger.error("Failed to parse user info for username={} with error={}".format(username, str(e)))
            return FAILED
        if 'status' not in nameAttributes:
            logger.error("Failed to parse user info for username={}, status not present in response output".format(username))
            return FAILED
        status = nameAttributes['status']

    roleString = ''
    realNameString = ''
    fullString = ''
    if groupsResponse.status_code == 429 or usernameResponse.status_code == 429:
        logger.error("Rate limit reached for IdP, failed to get user and group info for username={} with user "
                        "response status={} and user response={} and group response status={} and group response={}".format(username, usernameResponse.status_code, usernameResponse.text, groupsResponse.status_code, groupsResponse.text))
        return FAILED
    if groupsResponse.status_code != 200 or usernameResponse.status_code != 200:
        logger.error("Failed to get user and group info for username={} with user response status={} and user "
                        "response={} and group response status={} and group response={}".format(username, usernameResponse.status_code, usernameResponse.text, groupsResponse.status_code, groupsResponse.text))
        return FAILED
    else:
        logger.info("Successfully obtained user and group info for username={} with user response status={} and user "
                    "response={} and group response status={} and group response={}".format(username, usernameResponse.status_code, usernameResponse.text, groupsResponse.status_code, groupsResponse.text))    
    # Available statuses : Staged, Pending User Action, Active, Password Reset, Locked Out, Suspended, Deactivated
    # https://help.okta.com/en/prod/Content/Topics/Directory/end-user-states.htm
    if status not in {"ACTIVE", "PASSWORD_EXPIRED", "RECOVERY", "LOCKED_OUT"}:
        logger.error("User is not active in IdP for username={} with user status={}".format(username, status))
        return FAILED
    realNameString += nameAttributes['profile']['firstName'] + ' ' + nameAttributes['profile']['lastName']
    try:
        groupAttributes = json.loads(groupsResponse.text)
    except Exception as e:
        logger.error("Failed to parse group info for username={} with status={} and response={}".format(username, groupsResponse.status_code, groupsResponse.text))
        return FAILED

    base64UrlEncodedGroupNames = ['{}'.format(urlsafe_b64encode_to_str(group['profile']['name'])) for group in groupAttributes]
    roleString += ":".join(base64UrlEncodedGroupNames)

    base64UrlEncodedUsername = urlsafe_b64encode_to_str(username)
    base64UrlEncodedRealName = urlsafe_b64encode_to_str(realNameString)

    fullString += '{} --userInfo={};{};{} --encodedOutput=true'.format(SUCCESS, base64UrlEncodedUsername, base64UrlEncodedRealName, roleString)
    return fullString


if __name__ == "__main__":
    callName = sys.argv[1]
    dictIn = readInputs()

    if callName == "getUserInfo":
        response = getUserInfo(dictIn)
        print(response)
