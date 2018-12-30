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


class Context(object):
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
        'local_connections_enabled': 'bool',
        'remote_connections_enabled': 'bool',
        'no_connection_enabled': 'bool',
        'no_internet_enabled': 'bool',
        'restricted_interfaces_enabled': 'bool',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'minimum_agent_version': 'minimumAgentVersion',
        'local_connections_enabled': 'localConnectionsEnabled',
        'remote_connections_enabled': 'remoteConnectionsEnabled',
        'no_connection_enabled': 'noConnectionEnabled',
        'no_internet_enabled': 'noInternetEnabled',
        'restricted_interfaces_enabled': 'restrictedInterfacesEnabled',
        'id': 'ID'
    }

    def __init__(self, name=None, description=None, minimum_agent_version=None, local_connections_enabled=None, remote_connections_enabled=None, no_connection_enabled=None, no_internet_enabled=None, restricted_interfaces_enabled=None, id=None):  # noqa: E501
        """Context - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._minimum_agent_version = None
        self._local_connections_enabled = None
        self._remote_connections_enabled = None
        self._no_connection_enabled = None
        self._no_internet_enabled = None
        self._restricted_interfaces_enabled = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if minimum_agent_version is not None:
            self.minimum_agent_version = minimum_agent_version
        if local_connections_enabled is not None:
            self.local_connections_enabled = local_connections_enabled
        if remote_connections_enabled is not None:
            self.remote_connections_enabled = remote_connections_enabled
        if no_connection_enabled is not None:
            self.no_connection_enabled = no_connection_enabled
        if no_internet_enabled is not None:
            self.no_internet_enabled = no_internet_enabled
        if restricted_interfaces_enabled is not None:
            self.restricted_interfaces_enabled = restricted_interfaces_enabled
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this Context.  # noqa: E501

        Name of the context. Searchable as String.  # noqa: E501

        :return: The name of this Context.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this Context.

        Name of the context. Searchable as String.  # noqa: E501

        :param name: The name of this Context.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this Context.  # noqa: E501

        Description of the context. Searchable as String.  # noqa: E501

        :return: The description of this Context.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this Context.

        Description of the context. Searchable as String.  # noqa: E501

        :param description: The description of this Context.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def minimum_agent_version(self):
        """Gets the minimum_agent_version of this Context.  # noqa: E501

        Minimum supported agent version.  # noqa: E501

        :return: The minimum_agent_version of this Context.  # noqa: E501
        :rtype: str
        """
        return self._minimum_agent_version

    @minimum_agent_version.setter
    def minimum_agent_version(self, minimum_agent_version):
        """Sets the minimum_agent_version of this Context.

        Minimum supported agent version.  # noqa: E501

        :param minimum_agent_version: The minimum_agent_version of this Context.  # noqa: E501
        :type: str
        """

        self._minimum_agent_version = minimum_agent_version

    @property
    def local_connections_enabled(self):
        """Gets the local_connections_enabled of this Context.  # noqa: E501

        Specifies whether the context applies to connections that are locally conntected to a domain. Set to true to apply to locally connected.  # noqa: E501

        :return: The local_connections_enabled of this Context.  # noqa: E501
        :rtype: bool
        """
        return self._local_connections_enabled

    @local_connections_enabled.setter
    def local_connections_enabled(self, local_connections_enabled):
        """Sets the local_connections_enabled of this Context.

        Specifies whether the context applies to connections that are locally conntected to a domain. Set to true to apply to locally connected.  # noqa: E501

        :param local_connections_enabled: The local_connections_enabled of this Context.  # noqa: E501
        :type: bool
        """

        self._local_connections_enabled = local_connections_enabled

    @property
    def remote_connections_enabled(self):
        """Gets the remote_connections_enabled of this Context.  # noqa: E501

        Specifies whether the context applies to connections that are remotely conntected to a domain. Set to true to apply to remotely connected.  # noqa: E501

        :return: The remote_connections_enabled of this Context.  # noqa: E501
        :rtype: bool
        """
        return self._remote_connections_enabled

    @remote_connections_enabled.setter
    def remote_connections_enabled(self, remote_connections_enabled):
        """Sets the remote_connections_enabled of this Context.

        Specifies whether the context applies to connections that are remotely conntected to a domain. Set to true to apply to remotely connected.  # noqa: E501

        :param remote_connections_enabled: The remote_connections_enabled of this Context.  # noqa: E501
        :type: bool
        """

        self._remote_connections_enabled = remote_connections_enabled

    @property
    def no_connection_enabled(self):
        """Gets the no_connection_enabled of this Context.  # noqa: E501

        Specifies whether the context applies to connections that are no connection enabled. Set to true to apply to no connection enabled.  # noqa: E501

        :return: The no_connection_enabled of this Context.  # noqa: E501
        :rtype: bool
        """
        return self._no_connection_enabled

    @no_connection_enabled.setter
    def no_connection_enabled(self, no_connection_enabled):
        """Sets the no_connection_enabled of this Context.

        Specifies whether the context applies to connections that are no connection enabled. Set to true to apply to no connection enabled.  # noqa: E501

        :param no_connection_enabled: The no_connection_enabled of this Context.  # noqa: E501
        :type: bool
        """

        self._no_connection_enabled = no_connection_enabled

    @property
    def no_internet_enabled(self):
        """Gets the no_internet_enabled of this Context.  # noqa: E501

        Specifies whether the context applies to connections that are neither connection nor Internet enabled. Set to true to apply.  # noqa: E501

        :return: The no_internet_enabled of this Context.  # noqa: E501
        :rtype: bool
        """
        return self._no_internet_enabled

    @no_internet_enabled.setter
    def no_internet_enabled(self, no_internet_enabled):
        """Sets the no_internet_enabled of this Context.

        Specifies whether the context applies to connections that are neither connection nor Internet enabled. Set to true to apply.  # noqa: E501

        :param no_internet_enabled: The no_internet_enabled of this Context.  # noqa: E501
        :type: bool
        """

        self._no_internet_enabled = no_internet_enabled

    @property
    def restricted_interfaces_enabled(self):
        """Gets the restricted_interfaces_enabled of this Context.  # noqa: E501

        Controls if the firewall contents are restricted from view and duplication. Set to true if it's restricted. Searchable as Boolean.  # noqa: E501

        :return: The restricted_interfaces_enabled of this Context.  # noqa: E501
        :rtype: bool
        """
        return self._restricted_interfaces_enabled

    @restricted_interfaces_enabled.setter
    def restricted_interfaces_enabled(self, restricted_interfaces_enabled):
        """Sets the restricted_interfaces_enabled of this Context.

        Controls if the firewall contents are restricted from view and duplication. Set to true if it's restricted. Searchable as Boolean.  # noqa: E501

        :param restricted_interfaces_enabled: The restricted_interfaces_enabled of this Context.  # noqa: E501
        :type: bool
        """

        self._restricted_interfaces_enabled = restricted_interfaces_enabled

    @property
    def id(self):
        """Gets the id of this Context.  # noqa: E501

        ID of the context. Searchable as ID.  # noqa: E501

        :return: The id of this Context.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this Context.

        ID of the context. Searchable as ID.  # noqa: E501

        :param id: The id of this Context.  # noqa: E501
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
        if issubclass(Context, dict):
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
        if not isinstance(other, Context):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
