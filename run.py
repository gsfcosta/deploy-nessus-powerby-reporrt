#!/usr/bin/python3
from datetime import datetime
import requests, json, sys, os
import time
import urllib3
import pyodbc
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
credentials = {
    "accessKey": os.environ["ACC_KEY"],
    "secretKey": os.environ["SEC_KEY"]
    }
url = "https://<ip_nessus>:8834"
# folder_id = 10879 #INTERNO EDGE
db_hostname         = os.environ["DB_HOST"]
db_username         = os.environ["DB_USER"]
db_password         = os.environ["DB_PASS"]
db_name             = "<DATABASE>"

def start():
    headers = {
        'content-type': "application/json",
        'X-ApiKeys': f"accessKey={credentials['accessKey']}; secretKey={credentials['secretKey']}"
        }
    data = { 
            "format": "csv",
            "reportContents": {
                "csvColumns": {
                    "id": True,
                    "risk": True,
                    "hostname": True,
                    "plugin_name": True,
                    "cve": True,
                    "cvss": False,
                    "protocol": False,
                    "port": False,
                    "synopsis": False,
                    "description": False,
                    "solution": False,
                    "see_also": False,
                    "plugin_output": False,
                    }
                }
            }
    scans = requests.get(url + "/scans", headers=headers, verify=False)
    response = json.loads(scans.content)
    scans = response["scans"]
    folders = response["folders"]
    for scan in scans:
        try:
            folder_id = int(scan['folder_id'])
            for folder in folders:
                idx = int(folder["id"])
                if idx == folder_id:
                    folder_name = folder["name"]
            scan_id = str(scan['id'])
            scan_name = scan["name"]
            dat = scan['creation_date']
            scan_date = str(datetime.fromtimestamp(dat))
            scan_export = requests.post(url + "/scans/{}/export".format(scan_id), headers=headers, json=data, verify=False)
            response = json.loads(scan_export.content)
            file_id = str(response['file'])
            status = 'starting'
            while status not in ('ready', 'error'):
                time.sleep(1)
                sts = requests.get(url + "/scans/{}/export/{}/status".format(scan_id, file_id), headers=headers, verify=False)
                status = sts.json().get('status', 'error')
                print(status)
            download = requests.get(url + "/scans/{}/export/{}/download".format(scan_id, file_id), headers=headers, verify=False)
            content = download.text
            splited = content.split('\n')  
            for i in splited:
                try:
                    replaced = i.replace('\r', '')
                    replaced2 = replaced.replace('"', '')
                    spt = replaced2.split(',')
                    plugin_id = str(spt[0])
                    cve = str(spt[1])
                    if not cve:
                        cve = "None"   
                    risk = str(spt[2])
                    hostname = str(spt[3])
                    try:
                        plugin_name = spt[4].raplace("'", "")
                    except:
                        plugin_name = spt[4]
                    if plugin_id == "Plugin ID":
                        continue
                    else:
                        print(str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + "  Scan ID " + scan_id + " completed - " + hostname)
                        query_insert = f"""INSERT INTO table(folder_id, folder_name, scan_id, scan_name, plugin_id, hostname, risk, cve, name, scan_date) 
                        VALUES 
                        ({folder_id}, '{folder_name}', {scan_id}, '{scan_name}', '{plugin_id}', '{hostname}', '{risk}', '{cve}', '{plugin_name}', '{scan_date}')"""
                        cursor.execute(query_insert)
                        cursor.commit()
                except:
                    continue
        except BaseException as e:
            print(str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + "  Erro: " + str(e))
    print(str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + "  Finished Report")
    
try: 
    conexao = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};SERVER=%s;DATABASE=%s;UID=%s;PWD=%s" % (db_hostname, db_name, db_username, db_password))
    cursor = conexao.cursor()
    print(str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + "  Database login successful")
    query_insert = f"""truncate table dashboard_hosts"""
    cursor.execute(query_insert)
    cursor.commit()
    start()
except BaseException as e:
    print("Erro: " + str(e))
