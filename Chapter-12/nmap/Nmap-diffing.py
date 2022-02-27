#!/usr/bin/python3
# Nmap-diffing.py used to perform diffing operations based on Nmap reports
# David ROUTIN @rewt_1 - Purple Team Strategies (Packt Editions) - 2021

import re
import os
import shutil
import pprint
from pathlib import Path 
reports_raw = "/opt/ptx/nmap/reports_raw/"
last_known = "/opt/ptx/nmap/last_known/last_known.txt"
nmap_re = "Host: (?P<host>[^\s+]+).*?Ports:\s(?P<ports>.+?)\t+"
reports = sorted(Path(reports_raw).iterdir(), key=os.path.getmtime)
number_of_history_to_check = 3

reports_to_use = []

for n in range(-1*number_of_history_to_check,0):
    try:
        reports_to_use.append(reports[n])
    except:
        pass

if len(reports_to_use) == 0:
    print("No existing reports... Leaving")
    exit(1)

reports_to_use.reverse()

def parse_report(file,regex_touse=nmap_re):
    with open(file, "r") as f:
        data = f.read()

    try:
        collected = re.findall(regex_touse, data)
    except:
        pass

    #[('127.0.0.1', '22/open/tcp//ssh///, 631/open/tcp//ipp///, 8080/open/tcp//http-proxy///'), ('173.249.49.55', '22/open/tcp//ssh///')]
    results = {}

    for element in collected:
        try:
            host = element[0]
            ports = element[1].replace(" ", "").split(",")
            if not host in results:
                results[host] = ports
            else:
                for port in ports:
                    if not port in results[host][ports]:
                        results[host].append(port)
        except Exception as e:
            print(e)
    return results


# Check if last_known report exists, if not create, display a message, exit
latest_report = reports_to_use[0]
if not os.path.exists(last_known):
    shutil.copyfile(latest_report, last_known)
    print("No original reference found. Now created, please ensure to review the report below as it is now the first reference.\n")
    print(str(latest_report) + "\n")
    exit(2)

### Loading N history reports
history_reports = []
### we remove current from the list for history control
reports_to_use = reports_to_use[1:]

for report in reports_to_use:
    history_reports.append(parse_report(report))
### We had last_known in the report history
history_reports.append(parse_report(last_known))
### merging all reports together
merged_history = {}
for element in history_reports:
    for host in element.keys():
        try:
            merged_history[host]
        except:
            merged_history[host] = set()
        ports_l = element[host]
        for port in ports_l:
            merged_history[host].add(port)

anomalies = {}
latest_report_parsed=parse_report(latest_report)
# Now we compare latest report with last_known, we retun anomlies (things that exist in latest_report and not in last_known)
# Everything that does not exist become an anomaly

for host in latest_report_parsed:
    for port in latest_report_parsed[host]:
        if port not in merged_history[host]:
            if host not in anomalies:
                anomalies[host] = set()
            anomalies[host].add(port)

if len(anomalies) > 0:
    pprint.pprint(anomalies)

### The new model become the last_known
#shutil.copyfile(latest_report, last_known)
