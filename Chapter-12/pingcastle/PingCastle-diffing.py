#!/usr/bin/python3
# PingCastle-diffing.py used to perform diffing operations based on PingCastle reports
# David ROUTIN @rewt_1 - Purple Team Strategies (Packt Editions) - 2021

import deepdiff
import json
import pprint
import sys
import re
import os.path
from json import dumps
from xml.etree.ElementTree import fromstring
from xmljson import parker, Parker

if len(sys.argv) < 3:
    print("Usage: PingCastle-diffing.py previous_report.xml new_report.xml")
    exit(1)

for xmlreport in sys.argv:
    if os.path.isfile(xmlreport) is False:
        print(xmlreport + " does not exist... Leaving")
        exit(2)

old=sys.argv[1]
new=sys.argv[2]

### We are excluding specific fields to avoid false positive due only to time changes, creation dates etc
excludedRegex = [
     r".+Time", r".+Date.+", r".+Last", r".+Creation.+", r".+Number.+"
]

### This function open a file in XML format and return a string JSON object
def xmltojs(file):
    with open(file, "r") as f:
        d=f.read()
    j=dumps(parker.data(fromstring(d)))
    return j


old=json.loads(xmltojs(old))
new=json.loads(xmltojs(new))

### Cleaning results with specific pattern to avoid incoherent diffing, this can be probably improved and is not false positives proof, you have to adapt in your context if required
def clean_numbers(l):
    templ = []
    for e in l:
        ### temp element
        temp_e = {}
        temp_e = e
        if re.findall("day\(s\) ago|weak RSA key", e["Rationale"]):
            temp_e["Rationale"] = re.sub("\d+", "REPLACED", e["Rationale"])
        if re.findall("\[\d+\]", e["Rationale"]):
            temp_e["Rationale"] = re.sub("\d+", "REPLACED", e["Rationale"])
        templ.append(temp_e)
    return templ


old=clean_numbers(old["RiskRules"]["HealthcheckRiskRule"])
new=clean_numbers(new["RiskRules"]["HealthcheckRiskRule"])

anomalies=deepdiff.DeepDiff(old,new,ignore_order=True,exclude_regex_paths=excludedRegex)

if len(anomalies) > 0:
    pprint.pprint(anomalies)
