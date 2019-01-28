import json
import os
import urllib.request as urllibreq
import urllib.parse

# 3rd party dependencies
import deepsecurity as client
import deepsecurity
from deepsecurity.rest import ApiException as api_exception


def lambda_handler(event, context):
    global DSM
    global configuration
    configuration = client.Configuration()
    # DSM_policy = client.PoliciesApi(client.ApiClient(configuration))
    # DSM_client = client.ComputersApi(client.ApiClient(configuration))

    ds_api_key = '2:CC8BLAbBl8VH5sfPFjygafiV7heQc9fkHhDWkNjsxRk='

    ds_hostname = 'app.deepsecurity.trendmicro.com'
    ds_port = '443'

    # ds_ignore_ssl_validation = None
    # if 'dsIgnoreSslValidation' in os.environ: ds_ignore_ssl_validation = os.environ['dsIgnoreSslValidation']

    try:
        # DSM connection string
        configuration.host = 'https://' + ds_hostname + ':' + ds_port + '/api'
        configuration.verify_ssl = False
        # Authentication
        configuration.api_key['api-secret-key'] = ds_api_key
        api_version = 'v1'

        print("Signed into Deep Security")
    except api_exception as ex:
        print("Could not successfully sign into Deep Security. Threw exception: {}".format(ex))

    # From here we have to fetch data
    DSM_computer = client.ComputersApi(client.ApiClient(configuration))

    try:
        # NEED TO CHANGE THIS CODE TO SEARCH SPECIFIC INSTANCE ID
        search_filter = deepsecurity.SearchFilter()
        overrides = False

        response = DSM_computer.search_computers('v1', search_filter=search_filter, overrides=overrides)

        for computer in response.computers:
            if computer.ec2_virtual_machine_summary.instance_id == 'i-0ab687235eddfb3ad':
                attr = vars(computer)
                instance_in_ds = attr['_id']
                api_instance = deepsecurity.ScheduledTasksApi(deepsecurity.ApiClient(configuration))
                scheduled_task = deepsecurity.ScheduledTask().scan_for_recommendations_task_parameters
                res = api_instance.create_scheduled_task(scheduled_task, api_version)


        print("Found the instance in Deep Security as computer {}".format(len(response.computers)))
    except api_exception as ex:
        print("Could not find the instance in Deep Security. Threw exception: {}".format(ex))

lambda_handler(None, None)