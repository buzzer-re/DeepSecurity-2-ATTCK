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
        self.attck_navigator =  {
            "name": "Deep Security ATT&CK",
            "version": "2.1",
            "domain": "mitre-enterprise",
            "description": "An generated Deep Security ATT&CK matrix",
            "filters": {
                "stages": [
                    "act"
                ],
                "platforms": [
                    "windows",
                    "linux",
                    "mac"
                ]
            },
            "sorting": 0,
            "viewMode": 0,
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
            "selectTechniquesAcrossTactics": True
        }

        self.used_ruleset = {}
        self.used_attck_rules = {}

    def process_rules(self,rules, module_name, update = True):
        self.used_attck_rules = {}

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
            self.used_attck_rules[module_rule.id] = rule_match

            for techID in rule_match['rules']:
                self.attck_navigator['techniques'].append({
                    "techniqueID": techID,
                    "comment": "{} Rule applied by {}".format(rule_match['description'], module_name),
                    "color": "#31a354",
                    "enabled": True
                })
        
        return self.used_attck_rules
    
    def get_used_rules(self,computers, to_json=True):
        module_id_rules = {}
        for c in computers:
            if c.integrity_monitoring.rule_ids is not None:
                for comp_rule in c.integrity_monitoring.rule_ids:
                    if comp_rule not in module_id_rules and comp_rule in self.used_attck_rules:
                        module_id_rules[comp_rule] = True

            if c.intrusion_prevention.rule_ids is not None:
                for comp_rule in c.intrusion_prevention.rule_ids:
                    if comp_rule not in module_id_rules and comp_rule in self.used_attck_rules:
                        module_id_rules[comp_rule] = True

        for valid_rule in module_id_rules.keys():
            for rule in self.used_attck_rules[valid_rule]['rules']:
                self.attck_navigator['techniques'].append({
                    "techniqueID": rule,
                    "comment": "{} Rule applied by {}".format(self.used_attck_rules[valid_rule]['description'], self.used_attck_rules[valid_rule]['module_name']),
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

    attck_ds.process_rules(ips_rules, module_name = "Integrity Monitor")
    attck_ds.process_rules(im_rules,  module_name = "Intrusion Prevension")

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
