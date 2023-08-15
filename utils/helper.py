import pandas as pd
import requests
import time
import csv
import numpy as np
from requests.auth import HTTPBasicAuth
import traceback




def get_cve_info(cve_id,count,bar,API):
    bar.text("processing :"+cve_id+".  Fetching CVE details")
    code=400
    headers = {'apiKey': API}
    try:
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",headers=headers)
        #response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        count=count+1
        code=response.status_code
        bar.text(code)
        bar.text(response.headers)
        bar.text(response.content)
    except:
        code=400
        #bar.text("API ERROR NOW GOING TO LOOP")


    #print(response.content)
    while(code!=200):
        #print(cve_id)
        bar.text("Total calls:"+str(count))
        bar.text("looping")
        try:
            time.sleep(1)
            response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",headers=headers)
            #response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
            code = response.status_code
            code = response.status_code
            bar.text("error code:"+str(code))
        except:
            time.sleep(10)
            #print("looping:"+ str(response.headers))
            code=400

        #print(response)
        #break
    if response.status_code == 200:
        data= response.json()
        cisa=False
        cvssv=''
        #print(data)
        datacve={"cisa":False,"cvss_score":0}
        if data['totalResults']==0:
            datacve={"cisa":"Invalid CVE","cvss_score":"Invalid CVE"}
            return datacve
        try:
            #print(data['vulnerabilities'])
            if "cvssMetricV31"  in data['vulnerabilities'][0]['cve']['metrics']:
                cvssv="cvssMetricV31"
            elif "cvssMetricV30"  in data['vulnerabilities'][0]['cve']['metrics']:
                cvssv="cvssMetricV30"
            elif "cvssMetricV2"  in data['vulnerabilities'][0]['cve']['metrics']:
                cvssv="cvssMetricV2"

            if cvssv=='':
                return datacve
            cvss_score = data['vulnerabilities'][0]['cve']['metrics'][cvssv][0]['cvssData']['baseScore']

            value=data['vulnerabilities'][0]['cve']['cisaExploitAdd']
            cisa=True
            datacve['cvss_score']=cvss_score
            datacve['cisa']=True
        except KeyError:
            datacve['cisa']=False
            datacve['cvss_score'] = data['vulnerabilities'][0]['cve']['metrics'][cvssv][0]['cvssData']['baseScore']
        except Exception as e:
            traceback.print_exc()
            #print(Exception,e)
        return datacve
    else:
        return None

def get_epss_score(cve_id,bar,API):
    auth = HTTPBasicAuth('apiKey', API)
    status=400
    try:
        response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}",auth=auth)
        #response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        status=response.status_code
    except:
        time.sleep(10)
        #response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", auth=auth)
    while(status!=200):
        try:
            time.sleep(1)
            response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}",auth=auth)
            #response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
            bar.text("looping")
            status = response.status_code
        except:
            status=440
            time.sleep(10)


        #break
    if response.status_code == 200:
        try:
            data=response.json()
            if data['total']==0:
                epss_score='Invalid CVE'
                return epss_score
            epss_arr=data['data']
            epss_score=epss_arr[0]['epss']
            return epss_score
        except:
            return None
    else:
        return None

def process(cve,bar,output,verbos,API):
    count=0
    bar.text("Processing: " + cve)
    #bar(0.2)
    data = get_cve_info(cve,count,bar,API)

    #bar(0.6)
    count=count+1
    #print("data: "+str(data))
    cvss_score=data['cvss_score']

    # time.sleep(1)
    #print("got cvss: " + str(cvss_score))
    epss_score = get_epss_score(cve,bar,API)


    #bar(0.2)
    bar.text("Got EPSS: " + str(epss_score))
    #time.sleep(1)
    cisa = data['cisa']
    priority = ""
    if cisa=="Invalid CVE":
        if verbos:
            output.append([cve,cvss_score,epss_score,cisa,priority])
        else:
            output.append([cve,priority])
        return output


    bar.text("got CISA:" + str(cisa))
    if cvss_score == None or epss_score == None or cisa == None:
        return

    if (cisa == True or (float(epss_score) > 0.2 and float(cvss_score) > 6.0)):
        priority = 'Critical'

    elif ( float(epss_score) < 0.2 and float(cvss_score) > 6.0) :
        priority = 'Medium'
    elif (float(epss_score) > 0.2 and float(cvss_score) < 6.0 ):
        priority = 'High'
    elif ( float(epss_score) < 0.2 and float(cvss_score) < 6.0 ):
        priority = 'Low'
    if verbos:
        output.append([cve,cvss_score,epss_score,cisa,priority])

    else:
        output.append([cve,priority])
    return output
    #df = pd.DataFrame(result_list, columns=['CVE', 'QID','Title','Original Severity', 'CVSS', 'EPSS', 'CISA', 'INFA Severity'])
    #df.to_csv('QualysVMinfaScore_Platform.csv', index=False)
