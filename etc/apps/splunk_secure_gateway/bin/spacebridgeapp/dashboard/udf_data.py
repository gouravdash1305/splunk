"""
Copyright (C) 2009-2020 Splunk Inc. All Rights Reserved.
Data module for UDF objects
"""
import json
import os
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

import json
from splapp_protocol import common_pb2
from spacebridgeapp.data.base import SpacebridgeAppBase
from spacebridgeapp.util import constants
from spacebridgeapp.logging import setup_logging

LOGGER = setup_logging(constants.SPACEBRIDGE_APP_NAME + "_udf_data.log", "udf_data")


class UdfDataSource(SpacebridgeAppBase):
    """
    Data object for a UDF Data source
    """

    json = None  # type: str
    name = None  # type: str

    def __init__(self, name=None, json=None):
        self.name = name
        self.json = json
        self.datasource_id = UdfDataSource.create_datasource_id(name)

    @staticmethod
    def create_datasource_id(name):
        return name

    def set_protobuf(self, proto):
        proto.dataSourceId = self.datasource_id
        proto.name = self.name
        proto.json = json.dumps(self.json)

    def to_protobuf(self):
        """returns protobuf representation of this object

        Returns:
            DashboardData
        """
        proto = common_pb2.UDFDataSource()
        self.set_protobuf(proto)
        return proto


class UdfDashboardDescription(SpacebridgeAppBase):
    """
    Dashboard Description object specific to UDF dashboards

    """
    visualization_json = None  # type: str
    inputs_json = None  # type: str
    layout_json = None  # type: str
    descriptions = None  # type: str
    title = None  # type: str
    dashboard_id = None  # type: str
    list_searches = []
    global_inputs = []

    def __init__(self,
                 title=None,
                 description = None,
                 udf_data_sources = None,
                 visualization_json = None,
                 layout_json = None,
                 inputs_json = None,
                 dashboard_id = None,
                 global_inputs = None
                ):

        if not global_inputs:
            global_inputs = []

        self.title = title
        self.description = description
        self.udf_data_sources = udf_data_sources
        self.visualization_json = visualization_json
        self.layout_json = layout_json
        self.inputs_json = inputs_json
        self.dashboard_id = dashboard_id
        self.global_inputs = global_inputs

    @staticmethod
    def from_json(jsn):
        udf_dashboard_desc = UdfDashboardDescription()

        if 'title' in jsn:
            udf_dashboard_desc.title = jsn['title']
        if 'description' in jsn:
            udf_dashboard_desc.description = jsn['description']

        if 'dataSources' in jsn:
            udf_dashboard_desc.udf_data_sources = [UdfDataSource(j, jsn['dataSources'][j]) for j in jsn['dataSources']]

        if 'visualizations' in jsn:
            udf_dashboard_desc.visualizations = jsn['visualizations']

        if 'layout' in jsn:
            udf_dashboard_desc.layout_json = jsn['layout']

        if 'inputs' in jsn:
            udf_dashboard_desc.inputs_json = jsn['inputs']

        return udf_dashboard_desc

    def default_input_tokens(self):
        tokens = {}

        for input in self.global_inputs:
            input_options = self.inputs_json[input]
            token_name = input_options['options']['token']
            default_value = input_options.get('defaultValue')
            tokens[token_name] = default_value

        return tokens

    def set_protobuf(self, proto):
        """Takes a proto of type DashboardData and populates
         the fields with the corresponding class values

        Arguments:
        :type proto: common_pb2.UdfDashboardDescription
        """
        if self.title:
            proto.title = self.title

        if self.dashboard_id:
            proto.dashboardId = self.dashboard_id

        if self.description:
            proto.description = self.description

        if self.udf_data_sources:
            proto.udfDataSources.extend([udf_data_source.to_protobuf() for udf_data_source in self.udf_data_sources])

        if self.visualizations:
            proto.visualizationsJson = json.dumps(self.visualizations)

        if self.layout_json:
            proto.layoutJson = json.dumps(self.layout_json)

        if self.inputs_json:
            proto.inputsJson = json.dumps(self.inputs_json)

    def to_protobuf(self):
        """returns protobuf representation of this object

        Returns:
            DashboardData
        """
        proto = common_pb2.UDFDashboardDescription()
        self.set_protobuf(proto)
        return proto
