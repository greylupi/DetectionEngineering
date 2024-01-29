#This python script takes a TOML file containing elastic detection rules converts it to json and creates the detection
#rule in elastic. This contains only the minimum required fields + MITRE data(if it is included in the TOML.

import requests
import os
import tomllib

url = "hostname/api/detection_engine/rules"
api_key = "Insert APIKey"
headers = {
    'Content-Type':'application/json;charset=utf-8',
    'kbn-xsrf' : 'true',
    'authorization' : 'ApiKey ' + api_key
}

data = ""

for root, dirs, files in os.walk(r"filepath containing TOML files"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert_rule = tomllib.load(toml)

                if alert_rule['rule']['type'] == "query":
                    required = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threat']
                elif alert_rule['rule']['type'] == "eql": #event correlation alert_rule
                    required = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language', 'threat']
                elif alert_rule['rule']['type'] == "threshold": #thrshold correlation alert_rule
                    required = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold', 'threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                for field in alert_rule['rule']:
                    if field in required:
                        if type(alert_rule['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert_rule['rule'][field]).replace("'","\"") + "," + "\n"
                        elif type(alert_rule['rule'][field]) == str:
                            data += "  " + "\"" + field + "\": \"" + str(alert_rule['rule'][field]).replace("\n", " ").replace("\"","\\\"") + "\"," + "\n"
                        elif type(alert_rule['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert_rule['rule'][field]) + "," + "\n"
                data += "   \"enabled\": true\n}"
            elastic_data = requests.post(url, headers=headers, data=data).json()
            print(elastic_data)
