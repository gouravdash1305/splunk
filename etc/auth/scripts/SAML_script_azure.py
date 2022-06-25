import requests
import json
from urllib.parse import quote

from commonAuth import *

# This is for getting SAML user information, it is an alternative to using SAML attribute
# query requests (AQR) which Azure AD does not support.
#
# Provide Azure API key credentials and base url in the authentication.conf
# file or using the Splunk Web UI
# (Settings > Authentication Methods > SAML Configuration > Authentication Extensions)
# and use the Azure API to extract user information.
#
# In authentication.conf, configure the 'scriptSecureArguments' setting to
# "apiKey:<your Azure API key>". For example:
#
# scriptSecureArguments = apiKey:<your Azure API key string>,baseUrl:<your Azure url>
#
# After you restart the Splunk platform, the platform encrypts your Azure credentials.
# For more information about Splunk platform configuration files, search the
# Splunk documentation for "about configuration files".
#
# In Splunk Web UI under Authentication Extensions > Script Secure Arguments:
# key = apiKey, value = <your Azure API key string>

USER_ENDPOINT = 'https://graph.microsoft.com/v1.0/users/'
USER_FILTER_ENDPOINT = 'https://graph.microsoft.com/v1.0/users?$filter=mail%20eq%20'
LOGIN_ENDPOINT = 'https://login.microsoftonline.com/'
GRAPH_SCOPE = 'https://graph.microsoft.com/.default'
CLIENT_CREDENTIALS = 'client_credentials'
GROUP_TYPE = 'groupType'
request_timeout = 10

def getAuthToken(tenantId, clientId, clientSecret, logger):
    tokenEndpoint = LOGIN_ENDPOINT + tenantId + "/oauth2/v2.0/token"  # To Generate OAuth2 Token

    # Retrieve Auth Token from Azure
    body = {
            'grant_type': CLIENT_CREDENTIALS,
            'scope': GRAPH_SCOPE,
            'client_id': clientId,
            'client_secret': clientSecret
             }

    logger.info("Requesting Authentication Token for client={}".format(clientId))

    auth_response = requests.post(tokenEndpoint, data=body, timeout=request_timeout)

    if auth_response.status_code != 200:
        logger.error("Failed to get authorization token for client={} with status={} and response={}".format(clientId, auth_response.status_code, auth_response.text))
        return FAILED

    try:
        auth_responseSTR = json.loads(auth_response.text)
    except Exception as e:
        logger.error("Failed to parse authorization token for client={} with error={}".format(clientId, str(e)))
        return FAILED
    return auth_responseSTR['access_token']

# Microsoft graph API does not allow using emails to query information 
# This function makes another API call to get the user's principal name
# from their email
def getPrincipalName(args, logger, apiKey, username):
    if not username:
        logger.error("Username is empty. Not executing API call")
        return FAILED

    logger.info("Requesting principal name for username={}".format(username))

    API_KEY_HEADER = 'Bearer ' + apiKey
    AZURE_HEADERS = {'Host': 'graph.microsoft.com', 'Authorization': API_KEY_HEADER}

    encoded_username = quote("'" + username + "'")

    usernameFilterUrl = USER_FILTER_ENDPOINT + encoded_username
    usernameFilterResponse = requests.request('GET', usernameFilterUrl, headers=AZURE_HEADERS, timeout=request_timeout)

    if usernameFilterResponse.status_code != 200:
        logger.error("Failed to get principal name for username={} with status={} and response={}".format(username, usernameFilterResponse.status_code, usernameFilterResponse.text))
        return FAILED

    try:
        filterValues = json.loads(usernameFilterResponse.text)
    except Exception as e:
        logger.error("Failed to parse principal name for username={} with error={}".format(username, str(e)))
        return FAILED

    # API will return 200 even if the user doesn't exist
    if len(filterValues['value']) == 0:
        logger.info("Empty response returned for principal name for username={}".format(username))
        return ""
    logger.info("Found principal name: {}".format(filterValues['value'][0]['userPrincipalName']))
    return filterValues['value'][0]['userPrincipalName']


def getUserInfo(args, logger, apiKey, username):

    # Construct script response with the original username since 
    # we might be using a different username to get user info
    originalUsername = args['username']

    API_KEY_HEADER = 'Bearer ' + apiKey
    AZURE_HEADERS = {'Host': 'graph.microsoft.com', 'Authorization': API_KEY_HEADER}

    encoded_username = quote(username)
    realNameString = ''
    fullString = ''
    rolesString = ''

    usernameUrl = USER_ENDPOINT + encoded_username
    usernameResponse = requests.request('GET', usernameUrl, headers=AZURE_HEADERS, timeout=request_timeout)

    if usernameResponse.status_code != 200:
        logger.error("Failed to get user info for username={} with status={} and response={}".format(username, usernameResponse.status_code, usernameResponse.text))
        return FAILED

    try:
        nameAttributes = json.loads(usernameResponse.text)
    except Exception as e:
        logger.error("Failed to parse user info for username={} with error={}".format(username, str(e)))
        return FAILED

    realNameString += nameAttributes['displayName']

    # Construct a groups endpoint with the user's object ID
    groupsUrl = USER_ENDPOINT + encoded_username

    if GROUP_TYPE in args and args[GROUP_TYPE] == 'transitive':
        logger.info("Using transitive groups endpoint to query groups for username={}".format(username))
        groupsUrl += '/transitiveMemberOf'
    else:
        logger.info("Using direct groups endpoint to query groups for username={}".format(username))
        groupsUrl += '/memberOf'

    groupsUrl += '?$top=999'
    while groupsUrl:
        groupsResponse = requests.request('GET', groupsUrl, headers=AZURE_HEADERS, timeout=request_timeout)
        if groupsResponse.status_code != 200:
            logger.error("Failed to get user group membership for username={} with status={} and response={}".format(username, groupsResponse.status_code, groupsResponse.text))
            return FAILED

        try:
            groupsResponseSTR = json.loads(groupsResponse.text)
        except Exception as e:
            logger.error("Failed to parse user groups response for username={} with error={}".format(username, str(e)))
            return FAILED

        if groupsResponseSTR['value']:
            groupIds = [urlsafe_b64encode_to_str(group['id']) for group in groupsResponseSTR['value']]
            rolesString += ":".join(groupIds)
            if '@odata.nextLink' in groupsResponseSTR:
                groupsUrl = groupsResponseSTR['@odata.nextLink']
            else:
                groupsUrl = None
    # Returning the id associated with each group the user is a part of SAML has to be set up to use group id
    # from Azure AD as SAML group name Ref: customer case &
    # https://www.splunk.com/en_us/blog/cloud/configuring-microsoft-s-azure-security-assertion-markup-language
    # -saml-single-sign-on-sso-with-splunk-cloud-azure-portal.htm

    base64UrlEncodedUsername = urlsafe_b64encode_to_str(originalUsername)
    base64UrlEncodedRealName = urlsafe_b64encode_to_str(realNameString)

    fullString += '{} --userInfo={};{};{} --encodedOutput=true'.format(SUCCESS, base64UrlEncodedUsername, base64UrlEncodedRealName, rolesString)
    return fullString

def login(args, logger, apiKey, username):

    API_KEY_HEADER = 'Bearer ' + apiKey
    AZURE_HEADERS = {'Host': 'graph.microsoft.com', 'Authorization': API_KEY_HEADER}
    encoded_username = quote(username)
    fullString = ''
    rolesString = ''
    usernameUrl = USER_ENDPOINT + encoded_username
    usernameResponse = requests.request('GET', usernameUrl, headers=AZURE_HEADERS, timeout=request_timeout)
    if usernameResponse.status_code != 200:
        logger.error("Failed to get user info for username={} with status={} and response={}".format(username, usernameResponse.status_code, usernameResponse.text))
        return FAILED
    try:
        nameAttributes = json.loads(usernameResponse.text)
    except Exception as e:
        logger.error("Failed to parse user info for username={} with error={}".format(username, str(e)))
        return FAILED
    # Construct a groups endpoint with the user's object ID
    groupsUrl = USER_ENDPOINT + encoded_username

    if GROUP_TYPE in args and args[GROUP_TYPE] == 'transitive':
        logger.info("Using transitive groups endpoint to query groups for username={}".format(username))
        groupsUrl += '/transitiveMemberOf'
    else:
        logger.info("Using direct groups endpoint to query groups for username={}".format(username))
        groupsUrl += '/memberOf'

    groupsUrl += '?$top=999'

    while groupsUrl:
        groupsResponse = requests.request('GET', groupsUrl, headers=AZURE_HEADERS, timeout=request_timeout)
        if groupsResponse.status_code != 200:
            logger.error("Failed to get user group membership info for username={} with status={} and response={}".format(username, groupsResponse.status_code, groupsResponse.text))
            return FAILED

        try:
            groupsResponseSTR = json.loads(groupsResponse.text)
        except Exception as e:
            logger.error("Failed to parse user groups response for username={} with error={}".format(username, str(e)))
            return FAILED 
        allgroups = []
        if groupsResponseSTR['value']:
            groupIds = [urlsafe_b64encode_to_str(group['id']) for group in groupsResponseSTR['value']]
            allgroups += groupIds
            if '@odata.nextLink' in groupsResponseSTR:
                groupsUrl = groupsResponseSTR['@odata.nextLink']
            else:
                groupsUrl = None
    # Returning the id associated with each group the user is a part of SAML has to be set up to use group id
    # from Azure AD as SAML group name Ref: customer case &
    # https://www.splunk.com/en_us/blog/cloud/configuring-microsoft-s-azure-security-assertion-markup-language
    # -saml-single-sign-on-sso-with-splunk-cloud-azure-portal.htm
    for i in range(len(allgroups)):
        rolesString += '--groups={} '.format(allgroups[i])
    fullString += '{} {} --encodedOutput=true'.format(SUCCESS, rolesString)
    return fullString

if __name__ == "__main__":
    callName = sys.argv[1]
    dictIn = readInputs()
    logger = getLogger("{}/splunk_scripted_authentication_azure.log".format(logPath), "azure")

    apiKey = getAuthToken(dictIn['tenantId'], dictIn['clientId'], dictIn['clientSecret'], logger)
    # Exit script early if we cannot retrieve API access token
    if apiKey == FAILED:
        print(FAILED)

    else:
        # getPrincipalName will determine what username we use to query the graph API
        if callName == "getUserInfo":
            username = dictIn['username']
            principalName = getPrincipalName(dictIn, logger, apiKey, username)
            if principalName == FAILED:
                print(FAILED)
            else:
                if principalName:
                    username = principalName

                response = getUserInfo(dictIn, logger, apiKey, username)
                print(response)

        if callName == "login":
            username = dictIn['userInfo'].split(';')[0]
            principalName = getPrincipalName(dictIn, logger, apiKey, username)
            if principalName == FAILED:
                print(FAILED)
            else:
                if principalName:
                    username = principalName

                response = login(dictIn, logger, apiKey, username)
                print(response)

