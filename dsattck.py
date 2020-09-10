#!/usr/bin/python3

import deepsecurity
from api_loader import ApiLoader

from configparser import ConfigParser

import sys, warnings
import os

import re
import json


if not sys.warnoptions:
    warnings.simplefilter("ignore")


class DSAttck:
    def __init__(self):
        self.INTEGRIY_MONITORING = 'Integriy Monitoring'
        self.INTRUSION_PREVENSION = 'Intrusion Prevention'
        self.valid_modules = {
            self.INTEGRIY_MONITORING: True ,
            self.INTRUSION_PREVENSION: True
        }

        self.attck_navigator =  {
            "name": "Deep Security ATT&CK",
            "version": "3.0",
            "domain": "mitre-enterprise",
            "description": "An generated Deep Security ATT&CK matrix",
            "filters": {
                "stages": [
                    "act"
                ],
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS"
                ]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": False,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": [
                    "#ff6666",
                    "#ffe766",
                    "#8ec843"
                ],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [],
            "metadata": [],
            "showTaticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }

        self.used_attck_rules = {}

    def process_rules(self,rules, module_name, update = True):
        if module_name not in self.valid_modules:
            raise Exception("Invalid module {}".format(module_name))


        if not update:
            self.attck_navigator['techniques'].clear()
        
        regex_rule = '(\(ATT&CK .+\))'
        regex = re.compile(regex_rule)

        for module_rule in rules:
            search = regex.search(module_rule.name)
            rule_match = {}
            rule_match['name'] = module_rule.name
            rule_match['rules'] = search.group()[len('ATT&CK')+2:-1].split(',')
            rule_match['description'] = module_rule.description
            rule_match['module_name'] = module_name
            self.used_attck_rules.setdefault(module_name, {})
            self.used_attck_rules[module_name][module_rule.id] = rule_match

            for techID in rule_match['rules']:
                self.attck_navigator['techniques'].append({
                    "techniqueID": techID,
                    "comment": "{} Rule applied by {}".format(rule_match['description'], module_name),
                    "color": "#31a354",
                    "enabled": True
                })
        
        return self.used_attck_rules
    
    def get_used_rules(self,computers, to_json=True):
        
        integrity_monitoring_rules = self.used_attck_rules.get(self.INTEGRIY_MONITORING, {})
        intrusion_prevention_rules = self.used_attck_rules.get(self.INTRUSION_PREVENSION, {})
        module_id_rules = {}
        matched_rules = {} # Avoid duplicates

        for c in computers:
            if c.integrity_monitoring.rule_ids is not None:
                for comp_rule in c.integrity_monitoring.rule_ids:
                    if comp_rule not in matched_rule and comp_rule in integrity_monitoring_rules:
                        module_id_rules.setdefault(self.INTEGRIY_MONITORING, [])
                        module_id_rules[self.INTEGRIY_MONITORING].append(comp_rule)
                        matched_rules[comp_rule] = None

            if c.intrusion_prevention.rule_ids is not None:
                for comp_rule in c.intrusion_prevention.rule_ids:
                    if comp_rule not in matched_rules and comp_rule in intrusion_prevention_rules:
                        module_id_rules.setdefault(self.INTRUSION_PREVENSION, [])
                        module_id_rules[self.INTRUSION_PREVENSION].append(comp_rule)
                        matched_rules[comp_rule] = None


        for module_name, applied_rules in module_id_rules.items():
            for valid_rule in applied_rules:
                for rule in self.used_attck_rules[module_name][valid_rule]['rules']:
                    description = self.used_attck_rules[module_name][valid_rule]['description']
                    self.attck_navigator['techniques'].append({
                        "techniqueID": rule,
                        "comment": "{} Rule applied by {}".format(description, module_name),
                        "color": "#31a354",
                        "enabled": True
                    })


        raw_json = json.dumps(self.attck_navigator, indent=4) if to_json else self.attck_navigator
        self.attck_navigator['techniques'].clear()

        return raw_json

    def get_all_rules(self, to_json = True):
        raw_json = json.dumps(self.attck_navigator, indent=4) if to_json else self.attck_navigator
        self.attck_navigator['techniques'].clear()

        return raw_json if to_json else self.attck_navigator



CONF_NAME = "ds.conf"
ENV_FILE = "environment.json"
APPLIED_FILE = "applied_rules.json"


if __name__ == '__main__':

    if not os.access(CONF_NAME, os.R_OK):
        print('Unable to open {}'.format(CONF_NAME))
        sys.exit(1)

    config = ConfigParser()
    config.read(CONF_NAME)

    host = None
    api_key = None

    try:
        host = config.get('DS', 'host')
        api_key = config.get('DS', 'api_key')
    except:
        print("Invalid config file, make sure to follow the format as:\n[DS]\nhost=<URL>\napi_key=<API_KEY>\n")
        sys.exit(1)

    api_client = ApiLoader(host, api_key, 'v1')
    attck_ds = DSAttck()


    # Search criteria
    # Get all strings with ATT&CK as substr
    criteria = deepsecurity.SearchCriteria()
    criteria.field_name = "name"
    criteria.string_test = "equal"
    criteria.string_value = "%ATT&CK%"


    print("Requesting Integrity monitoring rules...")
    im_rules  = api_client.search_im_rules(criteria)

    print("Requesting Intrusion Prevention rules...")
    ips_rules = api_client.search_ips_rules(criteria)

    print("Processing rules...")

    attck_ds.process_rules(ips_rules, module_name = attck_ds.INTRUSION_PREVENSION)
    attck_ds.process_rules(im_rules,  module_name = attck_ds.INTEGRIY_MONITORING)

    print("Requesting all computers...")
    computers = api_client.request_computers()

    all_rules  = attck_ds.get_all_rules(to_json=True)
    
    print("Associating rules...")
    used_rules = attck_ds.get_used_rules(computers, to_json=True)

    with open('enviroment.json', 'w') as env_attck:
        env_attck.write(all_rules)
    
    with open('applied_attck.json', 'w') as used_attck:
        used_attck.write(used_rules)


    print("All rules can be found in enviroment.json file and used rules in applied_attck.json")
