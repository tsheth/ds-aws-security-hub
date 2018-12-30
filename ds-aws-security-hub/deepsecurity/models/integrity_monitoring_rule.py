# coding: utf-8

"""
    Trend Micro Deep Security API

    Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 11.2.225
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class IntegrityMonitoringRule(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'name': 'str',
        'description': 'str',
        'minimum_agent_version': 'str',
        'minimum_manager_version': 'str',
        'severity': 'str',
        'type': 'str',
        'original_issue': 'int',
        'last_updated': 'int',
        'identifier': 'str',
        'template': 'str',
        'registry_key_root': 'str',
        'registry_key_value': 'str',
        'registry_include_sub_keys': 'bool',
        'registry_included_values': 'list[str]',
        'registry_include_default_value': 'bool',
        'registry_excluded_values': 'list[str]',
        'registry_attributes': 'list[str]',
        'file_base_directory': 'str',
        'file_include_sub_directories': 'bool',
        'file_included_values': 'list[str]',
        'file_excluded_values': 'list[str]',
        'file_attributes': 'list[str]',
        'custom_xml': 'str',
        'alert_enabled': 'bool',
        'real_time_monitoring_enabled': 'bool',
        'recommendations_mode': 'str',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'minimum_agent_version': 'minimumAgentVersion',
        'minimum_manager_version': 'minimumManagerVersion',
        'severity': 'severity',
        'type': 'type',
        'original_issue': 'originalIssue',
        'last_updated': 'lastUpdated',
        'identifier': 'identifier',
        'template': 'template',
        'registry_key_root': 'registryKeyRoot',
        'registry_key_value': 'registryKeyValue',
        'registry_include_sub_keys': 'registryIncludeSubKeys',
        'registry_included_values': 'registryIncludedValues',
        'registry_include_default_value': 'registryIncludeDefaultValue',
        'registry_excluded_values': 'registryExcludedValues',
        'registry_attributes': 'registryAttributes',
        'file_base_directory': 'fileBaseDirectory',
        'file_include_sub_directories': 'fileIncludeSubDirectories',
        'file_included_values': 'fileIncludedValues',
        'file_excluded_values': 'fileExcludedValues',
        'file_attributes': 'fileAttributes',
        'custom_xml': 'customXML',
        'alert_enabled': 'alertEnabled',
        'real_time_monitoring_enabled': 'realTimeMonitoringEnabled',
        'recommendations_mode': 'recommendationsMode',
        'id': 'ID'
    }

    def __init__(self, name=None, description=None, minimum_agent_version=None, minimum_manager_version=None, severity=None, type=None, original_issue=None, last_updated=None, identifier=None, template=None, registry_key_root=None, registry_key_value=None, registry_include_sub_keys=None, registry_included_values=None, registry_include_default_value=None, registry_excluded_values=None, registry_attributes=None, file_base_directory=None, file_include_sub_directories=None, file_included_values=None, file_excluded_values=None, file_attributes=None, custom_xml=None, alert_enabled=None, real_time_monitoring_enabled=None, recommendations_mode=None, id=None):  # noqa: E501
        """IntegrityMonitoringRule - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._minimum_agent_version = None
        self._minimum_manager_version = None
        self._severity = None
        self._type = None
        self._original_issue = None
        self._last_updated = None
        self._identifier = None
        self._template = None
        self._registry_key_root = None
        self._registry_key_value = None
        self._registry_include_sub_keys = None
        self._registry_included_values = None
        self._registry_include_default_value = None
        self._registry_excluded_values = None
        self._registry_attributes = None
        self._file_base_directory = None
        self._file_include_sub_directories = None
        self._file_included_values = None
        self._file_excluded_values = None
        self._file_attributes = None
        self._custom_xml = None
        self._alert_enabled = None
        self._real_time_monitoring_enabled = None
        self._recommendations_mode = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if minimum_agent_version is not None:
            self.minimum_agent_version = minimum_agent_version
        if minimum_manager_version is not None:
            self.minimum_manager_version = minimum_manager_version
        if severity is not None:
            self.severity = severity
        if type is not None:
            self.type = type
        if original_issue is not None:
            self.original_issue = original_issue
        if last_updated is not None:
            self.last_updated = last_updated
        if identifier is not None:
            self.identifier = identifier
        if template is not None:
            self.template = template
        if registry_key_root is not None:
            self.registry_key_root = registry_key_root
        if registry_key_value is not None:
            self.registry_key_value = registry_key_value
        if registry_include_sub_keys is not None:
            self.registry_include_sub_keys = registry_include_sub_keys
        if registry_included_values is not None:
            self.registry_included_values = registry_included_values
        if registry_include_default_value is not None:
            self.registry_include_default_value = registry_include_default_value
        if registry_excluded_values is not None:
            self.registry_excluded_values = registry_excluded_values
        if registry_attributes is not None:
            self.registry_attributes = registry_attributes
        if file_base_directory is not None:
            self.file_base_directory = file_base_directory
        if file_include_sub_directories is not None:
            self.file_include_sub_directories = file_include_sub_directories
        if file_included_values is not None:
            self.file_included_values = file_included_values
        if file_excluded_values is not None:
            self.file_excluded_values = file_excluded_values
        if file_attributes is not None:
            self.file_attributes = file_attributes
        if custom_xml is not None:
            self.custom_xml = custom_xml
        if alert_enabled is not None:
            self.alert_enabled = alert_enabled
        if real_time_monitoring_enabled is not None:
            self.real_time_monitoring_enabled = real_time_monitoring_enabled
        if recommendations_mode is not None:
            self.recommendations_mode = recommendations_mode
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this IntegrityMonitoringRule.  # noqa: E501

        Name of the IntegrityMonitoringRule. Searchable as String.  # noqa: E501

        :return: The name of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this IntegrityMonitoringRule.

        Name of the IntegrityMonitoringRule. Searchable as String.  # noqa: E501

        :param name: The name of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this IntegrityMonitoringRule.  # noqa: E501

        Description of the IntegrityMonitoringRule. Searchable as String.  # noqa: E501

        :return: The description of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this IntegrityMonitoringRule.

        Description of the IntegrityMonitoringRule. Searchable as String.  # noqa: E501

        :param description: The description of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def minimum_agent_version(self):
        """Gets the minimum_agent_version of this IntegrityMonitoringRule.  # noqa: E501

        Minimum Deep Security Agent version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X.X format. Defaults to `6.0.0.0`. If an agent is not the minimum required version, the manager does not send the rule to the agent, and generates an alert. Searchable as String.  # noqa: E501

        :return: The minimum_agent_version of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._minimum_agent_version

    @minimum_agent_version.setter
    def minimum_agent_version(self, minimum_agent_version):
        """Sets the minimum_agent_version of this IntegrityMonitoringRule.

        Minimum Deep Security Agent version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X.X format. Defaults to `6.0.0.0`. If an agent is not the minimum required version, the manager does not send the rule to the agent, and generates an alert. Searchable as String.  # noqa: E501

        :param minimum_agent_version: The minimum_agent_version of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._minimum_agent_version = minimum_agent_version

    @property
    def minimum_manager_version(self):
        """Gets the minimum_manager_version of this IntegrityMonitoringRule.  # noqa: E501

        Minimum Deep Security Manager version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X format. Defaults to `6.0.0`. An alert will be raised if a manager that fails to meet the minimum manager version value tries to assign this rule to a host or profile. Searchable as String.  # noqa: E501

        :return: The minimum_manager_version of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._minimum_manager_version

    @minimum_manager_version.setter
    def minimum_manager_version(self, minimum_manager_version):
        """Sets the minimum_manager_version of this IntegrityMonitoringRule.

        Minimum Deep Security Manager version that supports the IntegrityMonitoringRule. This value is provided in the X.X.X format. Defaults to `6.0.0`. An alert will be raised if a manager that fails to meet the minimum manager version value tries to assign this rule to a host or profile. Searchable as String.  # noqa: E501

        :param minimum_manager_version: The minimum_manager_version of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._minimum_manager_version = minimum_manager_version

    @property
    def severity(self):
        """Gets the severity of this IntegrityMonitoringRule.  # noqa: E501

        Severity level of the event is multiplied by the computer's asset value to determine ranking. Ranking can be used to sort events with more business impact. Searchable as Choice.  # noqa: E501

        :return: The severity of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._severity

    @severity.setter
    def severity(self, severity):
        """Sets the severity of this IntegrityMonitoringRule.

        Severity level of the event is multiplied by the computer's asset value to determine ranking. Ranking can be used to sort events with more business impact. Searchable as Choice.  # noqa: E501

        :param severity: The severity of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["low", "medium", "high", "critical"]  # noqa: E501
        if severity not in allowed_values:
            raise ValueError(
                "Invalid value for `severity` ({0}), must be one of {1}"  # noqa: E501
                .format(severity, allowed_values)
            )

        self._severity = severity

    @property
    def type(self):
        """Gets the type of this IntegrityMonitoringRule.  # noqa: E501

        Type of the IntegrityMonitoringRule. If the rule is predefined by Trend Micro, it is set to `2`. If it is user created, it is set to `1`. Searchable as String.  # noqa: E501

        :return: The type of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this IntegrityMonitoringRule.

        Type of the IntegrityMonitoringRule. If the rule is predefined by Trend Micro, it is set to `2`. If it is user created, it is set to `1`. Searchable as String.  # noqa: E501

        :param type: The type of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def original_issue(self):
        """Gets the original_issue of this IntegrityMonitoringRule.  # noqa: E501

        Timestamp when the IntegrityMonitoringRule was originally issued by Trend Micro, in milliseconds since epoch.  Empty if the IntegrityMonitoringRule is user created. Searchable as Date.  # noqa: E501

        :return: The original_issue of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: int
        """
        return self._original_issue

    @original_issue.setter
    def original_issue(self, original_issue):
        """Sets the original_issue of this IntegrityMonitoringRule.

        Timestamp when the IntegrityMonitoringRule was originally issued by Trend Micro, in milliseconds since epoch.  Empty if the IntegrityMonitoringRule is user created. Searchable as Date.  # noqa: E501

        :param original_issue: The original_issue of this IntegrityMonitoringRule.  # noqa: E501
        :type: int
        """

        self._original_issue = original_issue

    @property
    def last_updated(self):
        """Gets the last_updated of this IntegrityMonitoringRule.  # noqa: E501

        Timestamp when the IntegrityMonitoringRule was last updated, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The last_updated of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: int
        """
        return self._last_updated

    @last_updated.setter
    def last_updated(self, last_updated):
        """Sets the last_updated of this IntegrityMonitoringRule.

        Timestamp when the IntegrityMonitoringRule was last updated, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param last_updated: The last_updated of this IntegrityMonitoringRule.  # noqa: E501
        :type: int
        """

        self._last_updated = last_updated

    @property
    def identifier(self):
        """Gets the identifier of this IntegrityMonitoringRule.  # noqa: E501

        Identifier of the IntegrityMonitoringRule from Trend Micro. Empty if the IntegrityMonitoringRule is user created. Searchable as String.  # noqa: E501

        :return: The identifier of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._identifier

    @identifier.setter
    def identifier(self, identifier):
        """Sets the identifier of this IntegrityMonitoringRule.

        Identifier of the IntegrityMonitoringRule from Trend Micro. Empty if the IntegrityMonitoringRule is user created. Searchable as String.  # noqa: E501

        :param identifier: The identifier of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._identifier = identifier

    @property
    def template(self):
        """Gets the template of this IntegrityMonitoringRule.  # noqa: E501

        Template which the IntegrityMonitoringRule follows.  # noqa: E501

        :return: The template of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._template

    @template.setter
    def template(self, template):
        """Sets the template of this IntegrityMonitoringRule.

        Template which the IntegrityMonitoringRule follows.  # noqa: E501

        :param template: The template of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["registry", "file", "custom"]  # noqa: E501
        if template not in allowed_values:
            raise ValueError(
                "Invalid value for `template` ({0}), must be one of {1}"  # noqa: E501
                .format(template, allowed_values)
            )

        self._template = template

    @property
    def registry_key_root(self):
        """Gets the registry_key_root of this IntegrityMonitoringRule.  # noqa: E501

        Registry hive which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_key_root of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._registry_key_root

    @registry_key_root.setter
    def registry_key_root(self, registry_key_root):
        """Sets the registry_key_root of this IntegrityMonitoringRule.

        Registry hive which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_key_root: The registry_key_root of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._registry_key_root = registry_key_root

    @property
    def registry_key_value(self):
        """Gets the registry_key_value of this IntegrityMonitoringRule.  # noqa: E501

        Registry key which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_key_value of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._registry_key_value

    @registry_key_value.setter
    def registry_key_value(self, registry_key_value):
        """Sets the registry_key_value of this IntegrityMonitoringRule.

        Registry key which is monitored by the IntegrityMonitoringRule. Empty if the IntegrityMonitoringRule does not monitor a registry key. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_key_value: The registry_key_value of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._registry_key_value = registry_key_value

    @property
    def registry_include_sub_keys(self):
        """Gets the registry_include_sub_keys of this IntegrityMonitoringRule.  # noqa: E501

        Controls whether the IntegrityMonitoringRule should also include subkeys of the registry key it monitors. Defaults to `false`. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_include_sub_keys of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: bool
        """
        return self._registry_include_sub_keys

    @registry_include_sub_keys.setter
    def registry_include_sub_keys(self, registry_include_sub_keys):
        """Sets the registry_include_sub_keys of this IntegrityMonitoringRule.

        Controls whether the IntegrityMonitoringRule should also include subkeys of the registry key it monitors. Defaults to `false`. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_include_sub_keys: The registry_include_sub_keys of this IntegrityMonitoringRule.  # noqa: E501
        :type: bool
        """

        self._registry_include_sub_keys = registry_include_sub_keys

    @property
    def registry_included_values(self):
        """Gets the registry_included_values of this IntegrityMonitoringRule.  # noqa: E501

        Registry key values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_included_values of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._registry_included_values

    @registry_included_values.setter
    def registry_included_values(self, registry_included_values):
        """Sets the registry_included_values of this IntegrityMonitoringRule.

        Registry key values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_included_values: The registry_included_values of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._registry_included_values = registry_included_values

    @property
    def registry_include_default_value(self):
        """Gets the registry_include_default_value of this IntegrityMonitoringRule.  # noqa: E501

        Controls whether the rule should monitor default registry key values. Defaults to `true`. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_include_default_value of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: bool
        """
        return self._registry_include_default_value

    @registry_include_default_value.setter
    def registry_include_default_value(self, registry_include_default_value):
        """Sets the registry_include_default_value of this IntegrityMonitoringRule.

        Controls whether the rule should monitor default registry key values. Defaults to `true`. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_include_default_value: The registry_include_default_value of this IntegrityMonitoringRule.  # noqa: E501
        :type: bool
        """

        self._registry_include_default_value = registry_include_default_value

    @property
    def registry_excluded_values(self):
        """Gets the registry_excluded_values of this IntegrityMonitoringRule.  # noqa: E501

        Registry key values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_excluded_values of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._registry_excluded_values

    @registry_excluded_values.setter
    def registry_excluded_values(self, registry_excluded_values):
        """Sets the registry_excluded_values of this IntegrityMonitoringRule.

        Registry key values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_excluded_values: The registry_excluded_values of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._registry_excluded_values = registry_excluded_values

    @property
    def registry_attributes(self):
        """Gets the registry_attributes of this IntegrityMonitoringRule.  # noqa: E501

        Registry key attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. Defaults to `STANDARD` which will monitor changes in registry size, content and type. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :return: The registry_attributes of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._registry_attributes

    @registry_attributes.setter
    def registry_attributes(self, registry_attributes):
        """Sets the registry_attributes of this IntegrityMonitoringRule.

        Registry key attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. Defaults to `STANDARD` which will monitor changes in registry size, content and type. Ignored if the IntegrityMonitoringRule does not monitor a registry key.  # noqa: E501

        :param registry_attributes: The registry_attributes of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._registry_attributes = registry_attributes

    @property
    def file_base_directory(self):
        """Gets the file_base_directory of this IntegrityMonitoringRule.  # noqa: E501

        Base of the file directory to be monitored by the IntegrityMonitoringRule. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :return: The file_base_directory of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._file_base_directory

    @file_base_directory.setter
    def file_base_directory(self, file_base_directory):
        """Sets the file_base_directory of this IntegrityMonitoringRule.

        Base of the file directory to be monitored by the IntegrityMonitoringRule. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :param file_base_directory: The file_base_directory of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._file_base_directory = file_base_directory

    @property
    def file_include_sub_directories(self):
        """Gets the file_include_sub_directories of this IntegrityMonitoringRule.  # noqa: E501

        Controls whether the IntegrityMonitoringRule should also monitor sub-directories of the base file directory that is associated with it. Defaults to `false`. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :return: The file_include_sub_directories of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: bool
        """
        return self._file_include_sub_directories

    @file_include_sub_directories.setter
    def file_include_sub_directories(self, file_include_sub_directories):
        """Sets the file_include_sub_directories of this IntegrityMonitoringRule.

        Controls whether the IntegrityMonitoringRule should also monitor sub-directories of the base file directory that is associated with it. Defaults to `false`. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :param file_include_sub_directories: The file_include_sub_directories of this IntegrityMonitoringRule.  # noqa: E501
        :type: bool
        """

        self._file_include_sub_directories = file_include_sub_directories

    @property
    def file_included_values(self):
        """Gets the file_included_values of this IntegrityMonitoringRule.  # noqa: E501

        File name values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Leaving this field blank when monitoring file directories will cause the IntegrityMonitoringRule to monitor all files in a directory. This can use significant system resources if the base directory contains numerous or large files. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :return: The file_included_values of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._file_included_values

    @file_included_values.setter
    def file_included_values(self, file_included_values):
        """Sets the file_included_values of this IntegrityMonitoringRule.

        File name values to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Leaving this field blank when monitoring file directories will cause the IntegrityMonitoringRule to monitor all files in a directory. This can use significant system resources if the base directory contains numerous or large files. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :param file_included_values: The file_included_values of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._file_included_values = file_included_values

    @property
    def file_excluded_values(self):
        """Gets the file_excluded_values of this IntegrityMonitoringRule.  # noqa: E501

        File name values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :return: The file_excluded_values of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._file_excluded_values

    @file_excluded_values.setter
    def file_excluded_values(self, file_excluded_values):
        """Sets the file_excluded_values of this IntegrityMonitoringRule.

        File name values to be ignored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. `?` matches a single character, while `*` matches zero or more characters. Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :param file_excluded_values: The file_excluded_values of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._file_excluded_values = file_excluded_values

    @property
    def file_attributes(self):
        """Gets the file_attributes of this IntegrityMonitoringRule.  # noqa: E501

        File attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. Defaults to `STANDARD` which will monitor changes in file creation date, last modified date, permissions, owner, group, size, content, flags (Windows) and SymLinkPath (Linux). Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :return: The file_attributes of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: list[str]
        """
        return self._file_attributes

    @file_attributes.setter
    def file_attributes(self, file_attributes):
        """Sets the file_attributes of this IntegrityMonitoringRule.

        File attributes to be monitored by the IntegrityMonitoringRule. JSON array or delimited by `\\n`. Defaults to `STANDARD` which will monitor changes in file creation date, last modified date, permissions, owner, group, size, content, flags (Windows) and SymLinkPath (Linux). Ignored if the IntegrityMonitoringRule does not monitor a file directory.  # noqa: E501

        :param file_attributes: The file_attributes of this IntegrityMonitoringRule.  # noqa: E501
        :type: list[str]
        """

        self._file_attributes = file_attributes

    @property
    def custom_xml(self):
        """Gets the custom_xml of this IntegrityMonitoringRule.  # noqa: E501

        Custom XML rules to be used by the IntegrityMonitoringRule. Custom XML rules must be encoded in the Base64 format. Ignored if the IntegrityMonitoringRule does not follow the `custom` template.  # noqa: E501

        :return: The custom_xml of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._custom_xml

    @custom_xml.setter
    def custom_xml(self, custom_xml):
        """Sets the custom_xml of this IntegrityMonitoringRule.

        Custom XML rules to be used by the IntegrityMonitoringRule. Custom XML rules must be encoded in the Base64 format. Ignored if the IntegrityMonitoringRule does not follow the `custom` template.  # noqa: E501

        :param custom_xml: The custom_xml of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """

        self._custom_xml = custom_xml

    @property
    def alert_enabled(self):
        """Gets the alert_enabled of this IntegrityMonitoringRule.  # noqa: E501

        Controls whether an alert should be made if an event related to the IntegrityMonitoringRule is logged. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :return: The alert_enabled of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: bool
        """
        return self._alert_enabled

    @alert_enabled.setter
    def alert_enabled(self, alert_enabled):
        """Sets the alert_enabled of this IntegrityMonitoringRule.

        Controls whether an alert should be made if an event related to the IntegrityMonitoringRule is logged. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :param alert_enabled: The alert_enabled of this IntegrityMonitoringRule.  # noqa: E501
        :type: bool
        """

        self._alert_enabled = alert_enabled

    @property
    def real_time_monitoring_enabled(self):
        """Gets the real_time_monitoring_enabled of this IntegrityMonitoringRule.  # noqa: E501

        Controls whether the IntegrityMonitoringRule is monitored in real time or during every scan. Defaults to `true` which indicates that it is monitored in real time. A value of `false` indicates that it will only be checked during scans. Searchable as Boolean.  # noqa: E501

        :return: The real_time_monitoring_enabled of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: bool
        """
        return self._real_time_monitoring_enabled

    @real_time_monitoring_enabled.setter
    def real_time_monitoring_enabled(self, real_time_monitoring_enabled):
        """Sets the real_time_monitoring_enabled of this IntegrityMonitoringRule.

        Controls whether the IntegrityMonitoringRule is monitored in real time or during every scan. Defaults to `true` which indicates that it is monitored in real time. A value of `false` indicates that it will only be checked during scans. Searchable as Boolean.  # noqa: E501

        :param real_time_monitoring_enabled: The real_time_monitoring_enabled of this IntegrityMonitoringRule.  # noqa: E501
        :type: bool
        """

        self._real_time_monitoring_enabled = real_time_monitoring_enabled

    @property
    def recommendations_mode(self):
        """Gets the recommendations_mode of this IntegrityMonitoringRule.  # noqa: E501

        Defines if the IntegrityMonitoringRule can/will be recommended by a recommendation scan. Defaults to `unknown` which means that it will not be recommended. Searchable as Choice.  # noqa: E501

        :return: The recommendations_mode of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: str
        """
        return self._recommendations_mode

    @recommendations_mode.setter
    def recommendations_mode(self, recommendations_mode):
        """Sets the recommendations_mode of this IntegrityMonitoringRule.

        Defines if the IntegrityMonitoringRule can/will be recommended by a recommendation scan. Defaults to `unknown` which means that it will not be recommended. Searchable as Choice.  # noqa: E501

        :param recommendations_mode: The recommendations_mode of this IntegrityMonitoringRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["unknown", "enabled", "ignored", "disabled"]  # noqa: E501
        if recommendations_mode not in allowed_values:
            raise ValueError(
                "Invalid value for `recommendations_mode` ({0}), must be one of {1}"  # noqa: E501
                .format(recommendations_mode, allowed_values)
            )

        self._recommendations_mode = recommendations_mode

    @property
    def id(self):
        """Gets the id of this IntegrityMonitoringRule.  # noqa: E501

        ID of the IntegrityMonitoringRule. Searchable as ID.  # noqa: E501

        :return: The id of this IntegrityMonitoringRule.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this IntegrityMonitoringRule.

        ID of the IntegrityMonitoringRule. Searchable as ID.  # noqa: E501

        :param id: The id of this IntegrityMonitoringRule.  # noqa: E501
        :type: int
        """

        self._id = id

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(IntegrityMonitoringRule, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, IntegrityMonitoringRule):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
