#!/usr/bin/env python3

HEADER = f"{'CVE-ID':<18}Infa Severity"+"\n"+("-"*36)
V_HEADER = f"{'CVE-ID':<18}{'Infa Severity':<18}{'EPSS':<9}{'CVSS':<6}{'VERSION':<10}{'SEVERITY':<10}CISA_KEV"+"\n"+("-"*81)

#EPSS_URL = "https://api.first.org/data/v1/epss"
#NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
csocbanner = """
           /$$           /$$       /$$                                       
          |__/          | $$      | $$                                        
  /$$$$$$  /$$  /$$$$$$$| $$   /$$| $$  /$$$$$$   /$$$$$$  /$$   /$$ /$$   /$$
 /$$__  $$| $$ /$$_____/| $$  /$$/| $$ /$$__  $$ /$$__  $$| $$  | $$|  $$ /$$/
| $$  \__/| $$|  $$$$$$ | $$$$$$/ | $$| $$  \ $$| $$  \ $$| $$  | $$ \  $$$$/ 
| $$      | $$ \____  $$| $$_  $$ | $$| $$  | $$| $$  | $$| $$  | $$  >$$  $$ 
| $$      | $$ /$$$$$$$/| $$ \  $$| $$|  $$$$$$/|  $$$$$$$|  $$$$$$$ /$$/\  $$
|__/      |__/|_______/ |__/  \__/|__/ \______/  \____  $$ \____  $$|__/  \__/
                                                 /$$  \ $$ /$$  | $$          
                                                |  $$$$$$/|  $$$$$$/          
                                                 \______/  \______/           
                                 
                                               by aku9669@gmail.com
"""""
