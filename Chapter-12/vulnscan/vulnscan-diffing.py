#!/usr/bin/env python3
import pandas
import glob 
import os 
import json
import code
import shutil
import pprint
from deepdiff import DeepDiff

reports_raw = "/opt/ptx/vulnscan/reports_raw/"
last_known = "/opt/ptx/vulnscan/last_known/last_output.json"
list_of_reports = glob.glob(reports_raw + "/*")

# We check if some reports are available in the new reports directory
if len(list_of_reports) == 0:
	print("Leaving... No report available\n")
	exit(1)

# Find the last report by modification date
latest_report = max(list_of_reports, key=os.path.getmtime) 

def groupby_vuln(report_file):
	# We convert the original report to a grouped version by risk_name and list object for impacted hosts
	with open(report_file, "r") as f:
		report = json.loads(f.read())
	df = pandas.DataFrame(report)
	# We want only High or Medium severity vulnerabilities
	df = df[ ( df["severity"]=="High" ) | ( df["severity"] == "Medium" )]
    # Change the "risk_name" and "impacted_host" string accordingly to your normalization
	data_raw = df.groupby("risk_name")["impacted_host"].apply(list).to_json()
	return json.loads(data_raw)

if not os.path.exists(last_known):
	shutil.copyfile(latest_report, last_known)
	print("No original reference found. Now created, please ensure to review the report below as it is now the first reference.\n")
	print(latest_report + "\n")
	exit(2)

### Reading  and aggregating previous output (last_known)
previous = groupby_vuln(last_known)
### Reading new output from the reports directory
new = groupby_vuln(latest_report)

### Diffing the two results
anomalies=DeepDiff(previous,new,ignore_order=True, verbose_level=2)
# We don't want removed_items (patched hosts since last time)
anomalies.pop("iterable_item_removed", None)
anomalies.pop("dictionary_item_removed", None)
if len(anomalies) > 0:
    pprint.pprint(anomalies)

# The new model become the last_known
shutil.copyfile(latest_report, last_known)
