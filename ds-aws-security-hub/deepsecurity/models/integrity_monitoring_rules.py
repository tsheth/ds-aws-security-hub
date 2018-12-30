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

from deepsecurity.models.integrity_monitoring_rule import IntegrityMonitoringRule  # noqa: F401,E501


class IntegrityMonitoringRules(object):
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
        'integrity_monitoring_rules': 'list[IntegrityMonitoringRule]'
    }

    attribute_map = {
        'integrity_monitoring_rules': 'integrityMonitoringRules'
    }

    def __init__(self, integrity_monitoring_rules=None):  # noqa: E501
        """IntegrityMonitoringRules - a model defined in Swagger"""  # noqa: E501

        self._integrity_monitoring_rules = None
        self.discriminator = None

        if integrity_monitoring_rules is not None:
            self.integrity_monitoring_rules = integrity_monitoring_rules

    @property
    def integrity_monitoring_rules(self):
        """Gets the integrity_monitoring_rules of this IntegrityMonitoringRules.  # noqa: E501


        :return: The integrity_monitoring_rules of this IntegrityMonitoringRules.  # noqa: E501
        :rtype: list[IntegrityMonitoringRule]
        """
        return self._integrity_monitoring_rules

    @integrity_monitoring_rules.setter
    def integrity_monitoring_rules(self, integrity_monitoring_rules):
        """Sets the integrity_monitoring_rules of this IntegrityMonitoringRules.


        :param integrity_monitoring_rules: The integrity_monitoring_rules of this IntegrityMonitoringRules.  # noqa: E501
        :type: list[IntegrityMonitoringRule]
        """

        self._integrity_monitoring_rules = integrity_monitoring_rules

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
        if issubclass(IntegrityMonitoringRules, dict):
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
        if not isinstance(other, IntegrityMonitoringRules):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
