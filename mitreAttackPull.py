import requests
import argparse
import sys

#requires the technique ID to be passed as an argument.

parser = argparse.ArgumentParser()
parser.add_argument("Technique ID", help = "[*] Please enter the Technique ID you need information for")
args = parser.parse_args()

technique_ID = sys.argv[1]

#pull mitre attack json from github
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {'accept' : 'application/json'}
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

print(mitreMapped[technique_ID]['name'])
print(mitreMapped[technique_ID]['url'])
