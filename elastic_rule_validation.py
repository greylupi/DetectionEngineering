#script to validate alert rule for elastic.
#target_file format TOML
#alert template requirements can be found at https://www.elastic.co/guide/en/security/current/rules-api-create.html

import tomllib
import sys

target_file = "filename.toml"

with open(target_file, "rb") as toml:
    alert_rule = tomllib.load(toml)


present_fields = []
missing_fields = []

if alert_rule['rule']['type'] == "query":
    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query']
elif alert_rule['rule']['type'] == "eql": #event correlation alert_rule
    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'language']
elif alert_rule['rule']['type'] == "threshold": #thrshold correlation alert_rule
    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'threshold']

for table in alert_rule:
    for field in alert_rule[table]:
        present_fields.append(field)

for field in required:
    if field not in present_fields:
        missing_fields.append(field)

if missing_fields:
    print("[*] Validation Error - Missing Required Field: " + str(missing_fields) + " in " + target_file)
else:
    print("[*] Validation Success - File is ready")

