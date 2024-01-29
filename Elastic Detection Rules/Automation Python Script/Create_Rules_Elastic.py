#This python script will create a detection rule in Elastic.

import requests

url = "host:port/api/detection_engine/rules"
api_key = "Insert API KEY"
headers = {
    'Content-Type':'application/json;charset=utf-8',
    'kbn-xsrf' : 'true',
    'authorization' : 'ApiKey ' + api_key
}

data = """
Insert json DETECTION rule from the elastic detection rule folder
"""
elastic_data = requests.post(url, headers=headers, data=data).json()

print(elastic_data)
