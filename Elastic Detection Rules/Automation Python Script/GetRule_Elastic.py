#Required detection rule ID from Elastic.
#This script sends a get request to get rule information.

import requests

url = "hostname/api/detection_engine/rules?rule_id="
id = "Insert Rule ID"
api_key = "Insert API key"
full_path = url + id
headers = {
    'Content-Type':'application/json;charset=utf-8',
    'kbn-xsrf' : 'true',
    'authorization' : 'ApiKey ' + api_key
}

elastic_data = requests.get(full_path, headers=headers).json()

print(elastic_data)
