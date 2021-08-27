# Created by Brennen Murray
# 
# Date Last Modified: 8/26/2021  
#
# This script is used to automate the blocking of malicous IP addresses in the Palo Alto Firewalls utilizing API/EDL's
# 
# Palo Alto API Documentation
# https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/explore-the-api
#

import requests
import xml.etree.ElementTree as ET
import time
from requests.packages import urllib3
from bs4 import BeautifulSoup as bs
import pandas as pd


#Supress SSL Warnings From Requests Library/Calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#
#   ENTER YOUR VAR'S HERE 
#
#Global Authentication Variables for the Palo Alto Firewall Connection
APIkey = ''
firewallIPAddress = ''
#
#
#

#This definition will reach out to the firewall based on specific definitions to pull log data, then digest it into a dataframe. Finally exporting to a temp CSV for long term retention logging and later use.
def queryFirewall():

    #Query Definitions
    type = 'log'
    logtype = 'threat'
    query = '(zone.src eq Untrust)'
    numberoflogs = '3000'

    #Send Palo Alto a Query Job
    jobrequest = requests.get('https://{}//api/?key={}&type={}&log-type={}&nlogs={}&query={}'.format(firewallIPAddress,APIkey,type,logtype,numberoflogs,query), verify=False)

    #Obtain the Job ID from the firewalls response
    string_xml = jobrequest.content
    xmlresponse = ET.fromstring(string_xml)
    jobid = xmlresponse.find('result').find('job')

    #Allow Palo Alto up to 60 Seconds to Gather Logs depending on hardware & query length
    time.sleep(60)

    #Access the Job Query Data.
    logdata = requests.get('https://{}/api/?key={}&type=log&job-id={}&action=get'.format(firewallIPAddress,APIkey,jobid.text), verify=False)

    #Parse for specific XML Pointers within the log level data
    soup = bs(logdata.text, 'lxml')
    RawSourceIP = soup.find_all('src')
    RawDateRecieved = soup.find_all('receive_time')
    RawSeverityRating = soup.find_all('severity')
    RawReasonForBlock = soup.find_all('threatid')
    
    #Orient the data found into a readable dataframe
    data = []
    for z,x,w,v in zip(RawSourceIP,RawDateRecieved,RawSeverityRating,RawReasonForBlock):
        data.append(
            {
                'Source IP':z.text,
                'Date':x.text,
                'Severity':w.text,
                'Reason for Block':v.text
            }
        )
    df = pd.DataFrame(data)

    #Ouput the Sliced Log Data into CSV File
    df.to_csv('C:\\PaloAlto_BlackList_Automation\\CultivatedLogFile.csv', mode='a', index=False)


#This defintion injests the cultivated CSV file and deduplicates the data set.
def removeDuplicates():

    DisctedLogFile = 'C:\\PaloAlto_BlackList_Automation\\CultivatedLogFile.csv'
    df = pd.read_csv(DisctedLogFile)

    df[~df.duplicated(subset=['Source IP'],)].to_csv('C:\\PaloAlto_BlackList_Automation\\DeduplicatedLogFile.csv', index=False)

#This definition will take the deduplicated CSV list and pipe the "Source IP" column into the EDL Text File
def appendToEDL():
    
    #File Location Variables
    EDLFile = "C:\\inetpub\\wwwroot\\PAEDL\\EDLlist.txt"
    DisctedLogFile = 'C:\\PaloAlto_BlackList_Automation\\DeduplicatedLogFile.csv'
  
    #Read csv into df, then convert into a list thats looped into the txt file.
    df = pd.read_csv(DisctedLogFile)
    a = list(df["Source IP"])
    with open(EDLFile, 'w') as f:
        for ip in a:
            f.write("%s\n" % ip)


queryFirewall()
removeDuplicates()
appendToEDL()

