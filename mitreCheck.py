#retrieves MITRE Attack Enterprise Framework data from Mitres Github.
#compares and checks alert rules created for elastic against the mitre framework
#check to ensure MITRE Tactic exists
#check to make sure the MITRE technique id is valid
#check to see if MITRE TID and name combination is valid
#check to see if the subTID + name entry is valid
#check to see if technique is deprecated

import requests
import tomllib
import os

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

headers = {
    'accept' : 'application/json'
}

response = requests.get(url, headers = headers).json()
dataMitre = response
mitreMapped = {}
for object in dataMitre['objects']:
    tactics = []
    if object['type'] == 'attack-pattern':
        if 'external_references' in object:
            for references in object['external_references']:
                if 'external_id' in references:
                    if ((references['external_id'].startswith("T"))):
                        if 'kill_chain_phases' in object:
                            for tactic in object['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                            technique = references['external_id']
                            name = object['name']
                            url = references['url']

                            if 'x_mitre_deprecated' in object:
                                deprecated = object['x_mitre_deprecated']
                                filtered_object = {'tactics' : str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                                mitreMapped[technique] = filtered_object
                            else:
                                filtered_object = {'tactics' : str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': False}
                                mitreMapped[technique] = filtered_object

alert_data = {}
filtered_object_array = []

for root, dirs, files in os.walk(r"C:\Users\marti\projects\Github\custom_alerts"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert_rule = tomllib.load(toml)
                filtered_object_array = []
                if alert_rule['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert_rule['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']

                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = "none"
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"


                        filtered_object = {'tactics' : tactic, 'technique_id': technique_id, 'technique_name': technique_name, 'subtechnique_id': subtechnique_id, 'subtechnique_name': subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array

mitre_tactic_list = ['none','reconnaissance','resource development','initial access','execution','persistence','privilege escalation', 'defense evasion', 'credential access','discovery','lateral movement','collection','command and control','exfiltration','impact']

for file in alert_data:
    for line in alert_data[file]:
        tactic = line['tactics'].lower()
        technique_id = line['technique_id']
        subtechnique_id = line['subtechnique_id']

        #check to ensure MITRE Tactic exists
        if tactic not in mitre_tactic_list:
            print("\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
            print("\n")
            print("Tactic " + "\"" + tactic + "\"" + " in " + file + " does not exist.")
            print("\n")

        #check to make sure the MITRE technique id is valid
        try:
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print("\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
            print("\n")
            print("Technique ID " + "\"" + technique_id+ "\"" + " in " + file + " does not exist.")
            print("\n")
            print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
            print("\n")

        #check to see if MITRE TID and name combination is valid
        try:
            mitre_name = mitreMapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                print("\n")
                print("MITRE Technique ID and name mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                print("\n")
                print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                print("\n")
        except KeyError:
            pass

        #check to see if the subTID + name entry is valid
        try:
            if subtechnique_id != "none":
                mitre_name = mitreMapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
                if alert_name != mitre_name:
                    print("\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                    print("\n")
                    print("MITRE Sub-Technique ID and name mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                    print("\n")
                    print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                    print("\n")
        except KeyError:
            pass

        #check to see if technique is deprecated
        try:
            if mitreMapped[technique_id]['deprecated'] == True:
                print("\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                print("\n")
                print("Deprecated Mitre Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
                print("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]")
                print("\n")
        except KeyError:
            pass
