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


class FirewallAssignments(object):
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
        'assigned_rule_ids': 'list[int]'
    }

    attribute_map = {
        'assigned_rule_ids': 'assignedRuleIDs'
    }

    def __init__(self, assigned_rule_ids=None):  # noqa: E501
        """FirewallAssignments - a model defined in Swagger"""  # noqa: E501

        self._assigned_rule_ids = None
        self.discriminator = None

        if assigned_rule_ids is not None:
            self.assigned_rule_ids = assigned_rule_ids

    @property
    def assigned_rule_ids(self):
        """Gets the assigned_rule_ids of this FirewallAssignments.  # noqa: E501

        List of assigned firewall rule IDs.  # noqa: E501

        :return: The assigned_rule_ids of this FirewallAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._assigned_rule_ids

    @assigned_rule_ids.setter
    def assigned_rule_ids(self, assigned_rule_ids):
        """Sets the assigned_rule_ids of this FirewallAssignments.

        List of assigned firewall rule IDs.  # noqa: E501

        :param assigned_rule_ids: The assigned_rule_ids of this FirewallAssignments.  # noqa: E501
        :type: list[int]
        """

        self._assigned_rule_ids = assigned_rule_ids

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
        if issubclass(FirewallAssignments, dict):
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
        if not isinstance(other, FirewallAssignments):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
