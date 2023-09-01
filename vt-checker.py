import argparse
import time
import requests
import validators
from urllib.parse import urlparse
import sys
import csv

API_KEY = '' # Your API Key Here

headers = {
        "accept": "application/json",
        "x-apikey": str(API_KEY)
    }

parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP and Domain analysis by OguzhanKanar")
parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
parser.add_argument("-u", "--url-list", help="bulk domain analysis")
parser.add_argument("-V", "--version", help="show program version", action="store_true")

args = parser.parse_args()

def checker(url,IOC):
    safeioc = IOC.replace('.','[.]')
    try:
        response = requests.get(url, headers=headers)
    except requests.ConnectTimeout as timeout:
        print('Connection Time Out. Error is: ')
        print(timeout)
    
    if response.status_code == 200:
        # print('Result for '+safeioc+' :')
        jsonResponse = response.json()
        # print(jsonResponse)
        if jsonResponse['data'] is None:
            print('There was an error submitting the domain for scanning.')
            # print(jsonResponse['verbose_msg'])
        # elif jsonResponse['response_code'] == -2:
        #     print('{!s} is queued for scanning.'.format(safeioc))
        else:
            print()
            print('{!s} was scanned successfully.'.format(safeioc))
            permalink = jsonResponse['data']['links']['self']
            try:
                epoch_time = jsonResponse["data"]["attributes"]["last_analysis_date"]
                scandate = time.strftime('%c', time.localtime(epoch_time))
            except:
                scandate = time.strftime('%c', time.localtime(time.time()))

            positives = int(jsonResponse['data']["attributes"]["last_analysis_stats"]['malicious']) + int(jsonResponse['data']["attributes"]["last_analysis_stats"]['suspicious'])

            total = int(jsonResponse['data']["attributes"]["last_analysis_stats"]['malicious']) + int(jsonResponse['data']["attributes"]["last_analysis_stats"]['suspicious']) + int(jsonResponse['data']["attributes"]["last_analysis_stats"]['harmless']) + int(jsonResponse['data']["attributes"]["last_analysis_stats"]['undetected']) + int(jsonResponse['data']["attributes"]["last_analysis_stats"]['timeout'])

            print()
            print('Link: ' + permalink)
            print('Scan Date: ' + scandate) 
            print('Positive: ' + str(positives) )
            print('Total Scan: ' + str(total) )
            print()
            sonuclar = [scandate,safeioc,str(positives),str(total),permalink]
            return sonuclar
            
    elif response.status_code == 204:
        return ('You may have exceeded your API request quota or rate limit.')
    else:
        pass

def EntryChecker(IOC):
    safeioc = IOC.replace('.','[.]')
    # print(IOC)
    try:
        if validators.ipv4(IOC):
            # print(IOC)
            url = "https://www.virustotal.com/api/v3/ip_addresses/"+str(IOC)
            sonuclar = checker(url,IOC)
            try:
                dataWriter = csv.writer(rfile, delimiter = ',')
                dataWriter.writerow(sonuclar)
            except:
                pass

        elif validators.domain(IOC):
            # print(IOC)
            url = "https://www.virustotal.com/api/v3/domains/"+str(IOC)
            sonuclar = checker(url,IOC)
            try:
                dataWriter = csv.writer(rfile, delimiter = ',')
                dataWriter.writerow(sonuclar)
            except:
                pass
            

        elif validators.url(IOC):
            new_IOC = urlparse(str(IOC)).netloc
            # print(new_IOC)
            EntryChecker(new_IOC)
        else:
            print("Fail the scan for "+IOC)
    except:
        sys.stderr.write('Failed check IOC: '+ str(IOC))



def IP_LIST_CHECKER(IP_LIST_PATH):
    IP_LIST = []
    with open(str(IP_LIST_PATH),'r') as iplist:
        IP_LIST = iplist.read().splitlines()
    for i in IP_LIST:
        sonuclar = EntryChecker(i)
        try:
            dataWriter = csv.writer(rfile, delimiter = ',')
            dataWriter.writerow(sonuclar)
        except:
            pass



def Domain_List_Checker(DOMAIN_LIST_PATH):
    DOMAIN_LIST = []
    with open(str(DOMAIN_LIST_PATH),'r') as domainlist:
        DOMAIN_LIST = domainlist.read().splitlines()
    for i in DOMAIN_LIST:
        sonuclar = EntryChecker(i)
        try:
            dataWriter = csv.writer(rfile, delimiter = ',')
            dataWriter.writerow(sonuclar)
        except:
            pass

def csv_creator():
    try:
        global rfile 
        rfile = open('results.csv', 'w+', newline='')
        dataWriter = csv.writer(rfile, delimiter = ',')
        header = ['Scan Date', 'IOC', '# of Positive Scans', '# of Total Scans', 'Permalink']
        dataWriter.writerow(header)

    except IOError as ioerr:
        print('Please ensure the file is closed.')
        print(ioerr)


# Check for --single-entry or -s
if args.single_entry:
    EntryChecker(args.single_entry)
# Check for --ip-list or -i
elif args.ip_list:
    IP_LIST_PATH = str(args.ip_list)
    csv_creator()
    IP_LIST_CHECKER(IP_LIST_PATH)
# Check for --url-list or -u
elif args.url_list:
    URL_LIST_PATH = str(args.url_list)
    csv_creator()
    Domain_List_Checker(URL_LIST_PATH)
# Check for --version or -V
elif args.version:
    print("VT API v3 IP Checker 1.0")
# Print usage information if no arguments are provided
else:
    print("usage: vt-checker.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u DOMAIN_LIST] [-V]")


