#elastic_rule validation.py upgrade. Hardcoded file path to retrieve a directory
#containing .toml files. Then takes those TOML files and verfies if the format is ok. 
#It also prints out the file.

import tomllib
import sys
import os

for root, dirs, files in os.walk(r"c:\Insert\file\path"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert_rule = tomllib.load(toml)
                print(alert_rule)

                present_fields = []
                missing_fields = []

                if alert_rule['rule']['type'] == "query":
                    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query']
                elif alert_rule['rule']['type'] == "eql": #event correlation alert_rule
                    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'language']
                elif alert_rule['rule']['type'] == "threshold": #thrshold correlation alert_rule
                    required = ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'threshold']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                for table in alert_rule:
                    for field in alert_rule[table]:
                        present_fields.append(field)

                for field in required:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print("\n")
                    print("\n")
                    print("[*] Validation Error - Missing Required Field: " + str(missing_fields) + " in " + file)
                    print("\n")
                    print("\n")
                else:
                    print("\n")
                    print("\n")
                    print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                    print("[*] Validation Success - File is ready.[*]")
                    print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                    print("\n")
                    print("\n")
