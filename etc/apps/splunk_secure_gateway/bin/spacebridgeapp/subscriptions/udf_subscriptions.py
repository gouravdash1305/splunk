"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.
Module which contains helper functions for UDF subscriptions
"""
from spacebridgeapp.data.dashboard_data import Search
from spacebridgeapp.dashboard.util import string_to_refresh_type


def create_search_from_datasource(datasource):
    """

    Take a data source object, extract out parameters such as search query, earliest, lates, etc. and creates
    a search object
    :type datasource: UdfDataSource
    returns Search
    """

    ds_jsn = datasource.json
    options = ds_jsn.get('options', {})
    query_param = options.get('queryParameters', {})

    query = options.get('query',  "")
    refresh = options.get('refresh', "")
    refresh_type = options.get('refreshType', "")
    earliest = query_param.get('earliest', "")
    latest = query_param.get('latest', "")

    return Search(
        earliest=earliest,
        latest=latest,
        refresh=refresh,
        refresh_type=string_to_refresh_type(refresh_type),
        query=query
    )

