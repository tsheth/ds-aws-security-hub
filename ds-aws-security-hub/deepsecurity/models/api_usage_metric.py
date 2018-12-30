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


class ApiUsageMetric(object):
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
        'api_type': 'str',
        'action': 'str',
        'method': 'str',
        '_date': 'int',
        'tenant_guid': 'str',
        'duration': 'int',
        'status_code': 'int',
        'authentication_method': 'str',
        'id': 'int'
    }

    attribute_map = {
        'api_type': 'apiType',
        'action': 'action',
        'method': 'method',
        '_date': 'date',
        'tenant_guid': 'tenantGUID',
        'duration': 'duration',
        'status_code': 'statusCode',
        'authentication_method': 'authenticationMethod',
        'id': 'ID'
    }

    def __init__(self, api_type=None, action=None, method=None, _date=None, tenant_guid=None, duration=None, status_code=None, authentication_method=None, id=None):  # noqa: E501
        """ApiUsageMetric - a model defined in Swagger"""  # noqa: E501

        self._api_type = None
        self._action = None
        self._method = None
        self.__date = None
        self._tenant_guid = None
        self._duration = None
        self._status_code = None
        self._authentication_method = None
        self._id = None
        self.discriminator = None

        if api_type is not None:
            self.api_type = api_type
        if action is not None:
            self.action = action
        if method is not None:
            self.method = method
        if _date is not None:
            self._date = _date
        if tenant_guid is not None:
            self.tenant_guid = tenant_guid
        if duration is not None:
            self.duration = duration
        if status_code is not None:
            self.status_code = status_code
        if authentication_method is not None:
            self.authentication_method = authentication_method
        if id is not None:
            self.id = id

    @property
    def api_type(self):
        """Gets the api_type of this ApiUsageMetric.  # noqa: E501

        Type of API called (\"REST\" or \"SOAP\"). Searchable as String.  # noqa: E501

        :return: The api_type of this ApiUsageMetric.  # noqa: E501
        :rtype: str
        """
        return self._api_type

    @api_type.setter
    def api_type(self, api_type):
        """Sets the api_type of this ApiUsageMetric.

        Type of API called (\"REST\" or \"SOAP\"). Searchable as String.  # noqa: E501

        :param api_type: The api_type of this ApiUsageMetric.  # noqa: E501
        :type: str
        """

        self._api_type = api_type

    @property
    def action(self):
        """Gets the action of this ApiUsageMetric.  # noqa: E501

        Http action (\"GET\", \"PUT\", \"POST\" or \"DELETE\"). Searchable as String.  # noqa: E501

        :return: The action of this ApiUsageMetric.  # noqa: E501
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """Sets the action of this ApiUsageMetric.

        Http action (\"GET\", \"PUT\", \"POST\" or \"DELETE\"). Searchable as String.  # noqa: E501

        :param action: The action of this ApiUsageMetric.  # noqa: E501
        :type: str
        """

        self._action = action

    @property
    def method(self):
        """Gets the method of this ApiUsageMetric.  # noqa: E501

        Method or API Endpoint called. Searchable as String.  # noqa: E501

        :return: The method of this ApiUsageMetric.  # noqa: E501
        :rtype: str
        """
        return self._method

    @method.setter
    def method(self, method):
        """Sets the method of this ApiUsageMetric.

        Method or API Endpoint called. Searchable as String.  # noqa: E501

        :param method: The method of this ApiUsageMetric.  # noqa: E501
        :type: str
        """

        self._method = method

    @property
    def _date(self):
        """Gets the _date of this ApiUsageMetric.  # noqa: E501

        Date of API call in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The _date of this ApiUsageMetric.  # noqa: E501
        :rtype: int
        """
        return self.__date

    @_date.setter
    def _date(self, _date):
        """Sets the _date of this ApiUsageMetric.

        Date of API call in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param _date: The _date of this ApiUsageMetric.  # noqa: E501
        :type: int
        """

        self.__date = _date

    @property
    def tenant_guid(self):
        """Gets the tenant_guid of this ApiUsageMetric.  # noqa: E501

        GUID of the tenant who called the API. Searchable as String.  # noqa: E501

        :return: The tenant_guid of this ApiUsageMetric.  # noqa: E501
        :rtype: str
        """
        return self._tenant_guid

    @tenant_guid.setter
    def tenant_guid(self, tenant_guid):
        """Sets the tenant_guid of this ApiUsageMetric.

        GUID of the tenant who called the API. Searchable as String.  # noqa: E501

        :param tenant_guid: The tenant_guid of this ApiUsageMetric.  # noqa: E501
        :type: str
        """

        self._tenant_guid = tenant_guid

    @property
    def duration(self):
        """Gets the duration of this ApiUsageMetric.  # noqa: E501

        Duration of the API call from request to response in milliseconds. Searchable as Numeric.  # noqa: E501

        :return: The duration of this ApiUsageMetric.  # noqa: E501
        :rtype: int
        """
        return self._duration

    @duration.setter
    def duration(self, duration):
        """Sets the duration of this ApiUsageMetric.

        Duration of the API call from request to response in milliseconds. Searchable as Numeric.  # noqa: E501

        :param duration: The duration of this ApiUsageMetric.  # noqa: E501
        :type: int
        """

        self._duration = duration

    @property
    def status_code(self):
        """Gets the status_code of this ApiUsageMetric.  # noqa: E501

        Http status code returned by the API. Searchable as Numeric.  # noqa: E501

        :return: The status_code of this ApiUsageMetric.  # noqa: E501
        :rtype: int
        """
        return self._status_code

    @status_code.setter
    def status_code(self, status_code):
        """Sets the status_code of this ApiUsageMetric.

        Http status code returned by the API. Searchable as Numeric.  # noqa: E501

        :param status_code: The status_code of this ApiUsageMetric.  # noqa: E501
        :type: int
        """

        self._status_code = status_code

    @property
    def authentication_method(self):
        """Gets the authentication_method of this ApiUsageMetric.  # noqa: E501

        Method used to authenticate the API call (\"sID\", \"API-Key\", or empty string). Searchable as String.  # noqa: E501

        :return: The authentication_method of this ApiUsageMetric.  # noqa: E501
        :rtype: str
        """
        return self._authentication_method

    @authentication_method.setter
    def authentication_method(self, authentication_method):
        """Sets the authentication_method of this ApiUsageMetric.

        Method used to authenticate the API call (\"sID\", \"API-Key\", or empty string). Searchable as String.  # noqa: E501

        :param authentication_method: The authentication_method of this ApiUsageMetric.  # noqa: E501
        :type: str
        """

        self._authentication_method = authentication_method

    @property
    def id(self):
        """Gets the id of this ApiUsageMetric.  # noqa: E501

        ID of the APIUsageMetric. Searchable as ID.  # noqa: E501

        :return: The id of this ApiUsageMetric.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ApiUsageMetric.

        ID of the APIUsageMetric. Searchable as ID.  # noqa: E501

        :param id: The id of this ApiUsageMetric.  # noqa: E501
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
        if issubclass(ApiUsageMetric, dict):
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
        if not isinstance(other, ApiUsageMetric):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
