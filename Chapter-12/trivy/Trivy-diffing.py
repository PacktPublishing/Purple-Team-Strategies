#!/usr/bin/python3
import json
import sys
import subprocess
import pandas
import os 
import shutil
import pprint
from deepdiff import DeepDiff

current_report = "/opt/ptx/trivy/reports_raw/current_report.json"
last_known = "/opt/ptx/trivy/last_known/last_output.json"
severity = "HIGH,CRITICAL"

def run_cmd(cmd):
    cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    cmd = cmd.stdout.read()
    return cmd

docker_images_l = run_cmd("docker image ls -q").split()
docker_images_l = [ image.decode("utf-8") for image in docker_images_l ]
js_output= []

for image_id in docker_images_l:
    cmd = run_cmd("docker image inspect " + image_id)
    get_docker_image_info = json.loads(cmd)
    name = "".join(get_docker_image_info[0]["RepoTags"])
    tempd = { "image_name": name, "image_id": image_id }
    ### perform the Trivy scan on the image
    try:
        report = run_cmd("trivy -f json -q --severity " + severity + " " + name)
    except Exception as e:
        pass
        print(str(e))
        continue
    tempd["report"] = json.loads(report)
    ### We may encouner multiple vulnerabilities list from different subpackages
    all_vuln = []
    for result in tempd["report"]["Results"]:
        all_vuln.append(result["Vulnerabilities"])
    tempd["report"] = [i for l in all_vuln for i in l]
    js_output.append(tempd)

current_report_content = js_output

def analyze_report(vulnerabilities):
    temp = pandas.DataFrame(vulnerabilities)
    temp["risk_name"] = temp["Severity"] + "/"  + temp["VulnerabilityID"] +  "/" + temp["Title"] + "\n------\n"
    temp = temp.groupby("PkgName")["risk_name"].apply(list).to_json()
    return json.loads(temp)

### Building resume version of a report:
def resume_report(image_report):
    temp = {}
    for image in image_report:
        image_name = image["image_name"]
        temp[image_name] = {}
        temp[image_name]["image_id"] = image["image_id"]
        vulnerabilities = image["report"]
        temp[image_name]["vuln"] = analyze_report(vulnerabilities)
    return temp

simplified_current_content = resume_report(current_report_content)

# Updating report
with open(current_report, "w") as f:
    f.write(json.dumps(simplified_current_content))

if not os.path.exists(last_known):
    shutil.copyfile(current_report, last_known)
    print("No original reference found. Now created, please ensure to review this report as it is now the reference.\n")
    exit(2)

with open(last_known, "r") as f:
    last_known_content = f.read()
last_known_content=json.loads(last_known_content)

###### DEEPDIFF
previous=json.loads(open(last_known, "r").read())
new=simplified_current_content
anomalies=DeepDiff(previous,new,ignore_order=True,verbose_level=2)
# We don't want removed_items (patched hosts since last time)
anomalies.pop("iterable_item_removed", None)
anomalies.pop("dictionary_item_removed", None)
if len(anomalies) > 0:
    pprint.pprint(anomalies)

# Current report become the last_known
shutil.copyfile(current_report, last_known)
