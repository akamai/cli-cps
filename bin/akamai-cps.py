"""
Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

"""
This code leverages akamai OPEN API. to control Certificates deployed in Akamai Network.
In case you need quick explanation contact the initiators.
Initiators: vbhat@akamai.com, aetsai@akamai.com, mkilmer@akamai.com, bdutia@akamai.com
"""

import json
from akamai.edgegrid import EdgeGridAuth
from cpsApiWrapper import cps
import argparse
import configparser
import requests
import os
import logging
import shutil
from prettytable import PrettyTable

#Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logFile = os.path.join('logs', 'CPSConfigKit_log.log')

#Set the format of logging in console and file seperately
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
consoleFormatter = logging.Formatter("%(message)s")
rootLogger = logging.getLogger()


logfileHandler = logging.FileHandler(logFile, mode='w')
logfileHandler.setFormatter(logFormatter)
rootLogger.addHandler(logfileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(consoleFormatter)
rootLogger.addHandler(consoleHandler)
#Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
rootLogger.setLevel(logging.INFO)

try:
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.expanduser("~"),'.edgerc'))
    client_token = config['papi']['client_token']
    client_secret = config['papi']['client_secret']
    access_token = config['papi']['access_token']
    access_hostname = config['papi']['host']
    session = requests.Session()
    session.auth = EdgeGridAuth(
                client_token = client_token,
                client_secret = client_secret,
                access_token = access_token
                )
except (NameError, AttributeError, KeyError):
    rootLogger.info('\nLooks like ' + os.path.join(os.path.expanduser("~"),'.edgerc') + ' is missing or has invalid entries\n')
    exit(-1)

#Main arguments
parser = argparse.ArgumentParser(description='OpenAPI credentials are read from ~/.edgerc file')
parser.add_argument("-help",help="Use -h for detailed help options",action="store_true")
parser.add_argument("--setup","-s",help="Initial setup to download all necessary Enrollments information",action="store_true")
parser.add_argument("--getCertificateDetails",help="Get detailed information about specific certificate",action="store_true")
parser.add_argument("--getCertificateStatus",help="Get current status about specific certificate",action="store_true")
parser.add_argument("--audit",help="Generate a complete audit report of all certificates",action="store_true")
parser.add_argument("--cn",help="Hostname/CommonName/SAN of certificate of interest")


#Additional arguments
#parser.add_argument("-verbose",help="Display detailed rule information for a specific version (only for -getDetail method with -version)", action="store_true")
parser.add_argument("--debug",help="DEBUG mode to generate additional logs for troubleshooting",action="store_true")
args = parser.parse_args()


#Check for valid command line arguments
if not args.setup and not args.getCertificateDetails and not args.cn and not args.audit and not args.debug:
    rootLogger.info("Use -h for help options")
    exit(-1)

#Override log level if user wants to run in debug mode
#Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
if args.debug:
    rootLogger.setLevel(logging.DEBUG)


if args.setup:
    rootLogger.info('Setting up required files.... please wait')
    #Create the wrapper object to make calls
    cpsObject = cps(access_hostname)
    rootLogger.info('Processing Enrollments...')
    enrollmentsPath = os.path.join('setup','enrollments')
    #Delete the groups folder before we start
    if os.path.exists(enrollmentsPath):
        shutil.rmtree(enrollmentsPath)
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)
    contractId = 'M-1O66EMG'
    enrollmentsResponse = cpsObject.listEnrollments(session, contractId)
    if enrollmentsResponse.status_code == 200:
        with open(os.path.join(enrollmentsPath,'enrollments.json'),'w') as enrollmentsFile:
            enrollmentsJson = enrollmentsResponse.json()
            #Find number of groups using len function
            totalEnrollments = len(enrollmentsJson['enrollments'])
            rootLogger.info('Total of ' + str(totalEnrollments) + ' enrollments are found.')
            enrollmentOutput = []
            for everyEnrollment in enrollmentsJson['enrollments']:
                enrollmentInfo = {}
                if 'csr' in everyEnrollment:
                    #print(json.dumps(everyEnrollment, indent = 4))
                    enrollmentInfo['cn'] = everyEnrollment['csr']['cn']
                    if 'sans' in everyEnrollment['csr'] and everyEnrollment['csr']['sans'] is not None:
                        enrollmentInfo['sans'] = everyEnrollment['csr']['sans']
                    enrollmentInfo['enrollmentId'] = int(everyEnrollment['location'].split('/')[-1])
                    enrollmentOutput.append(enrollmentInfo)
            enrollmentsFile.write(json.dumps(enrollmentOutput,indent=4))
            rootLogger.info('Enrollments details are stored in ' + '"' + os.path.join(enrollmentsPath,'enrollments.json') + '"')
    else:
        rootLogger.info('Unable to list Enrollments.')
        exit(-1)


if args.getCertificateDetails:
    if not args.cn:
        rootLogger.info('Hostname/CN/SAN is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup','enrollments')
    cpsObject = cps(access_hostname)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath,localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            #rootLogger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    rootLogger.info('Fetching details of ' + cn + ' with enrollmentId: ' + str(enrollmentId))
                    enrollmentDetails = cpsObject.getEnrollment(session, enrollmentId)
                    if enrollmentDetails.status_code == 200:
                        enrollmentDetailsJson = enrollmentDetails.json()
                        table = PrettyTable(['TYPE','SANS', 'STATUS','ADMIN_EMAIL'])
                        if 'sans' in enrollmentDetailsJson['csr']:
                            if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                                for eachSan in enrollmentDetailsJson['csr']['sans']:
                                    table.add_row([enrollmentDetailsJson['certificateType'],eachSan, 'ACTIVE',enrollmentDetailsJson['adminContact']['email']])
                            else:
                                for eachSan in enrollmentDetailsJson['csr']['sans']:
                                    table.add_row([enrollmentDetailsJson['certificateType'],eachSan, 'INACTIVE'],enrollmentDetailsJson['adminContact']['email'])
                        rootLogger.info(table)
                    else:
                        rootLogger.info( 'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                        exit(-1)
        else:
            rootLogger.info('Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

if args.getCertificateStatus:
    if not args.cn:
        rootLogger.info('Hostname/CN/SAN is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup','enrollments')
    cpsObject = cps(access_hostname)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath,localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            #rootLogger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    rootLogger.info('Fetching details of ' + cn + ' with enrollmentId: ' + str(enrollmentId))
                    enrollmentDetails = cpsObject.getEnrollment(session, enrollmentId)
                    if enrollmentDetails.status_code == 200:
                        enrollmentDetailsJson = enrollmentDetails.json()
                        if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                            rootLogger.info('The certificate is active, there are no current pending changes.')
                        elif 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) > 0:
                            changeId = int(enrollmentDetailsJson['pendingChanges'].split('/')[-1])
                            changeStatusResponse = cpsObject.getChangeStatus(session, enrollmentId, changeId)
                            if changeStatusResponse.status_code == 200:
                                changeStatusResponseJson = changeStatusResponse.json()
                                table = PrettyTable('STATUS', 'DESCRIPTION', 'ERROR')
                                if 'error' in changeStatusResponseJson and changeStatusResponseJson['error'] is not None:
                                    table.add_row(changeStatusResponseJson['statusInfo']['status'],changeStatusResponseJson['statusInfo']['description'],changeStatusResponseJson['error']['description'])
                                else:
                                    #There is no error
                                    table.add_row(changeStatusResponseJson['statusInfo']['status'],changeStatusResponseJson['statusInfo']['description'],'')
                                rootLogger.info(table)
                            else:
                                rootLogger.info('Unable to determine change status.')
                                exit(-1)
                        else:
                            rootLogger.info('Unable to determine change status.')
                            exit(-1)

                    else:
                        rootLogger.info( 'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                        exit(-1)
        else:
            rootLogger.info('Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

if args.audit:
    enrollmentsPath = os.path.join('setup','enrollments')
    if not os.path.exists('output'):
        os.makedirs('output')
    outputFile = os.path.join('output', 'CPSAudit.csv')
    with open(os.path.join('output','CPSAudit.csv'),'w') as fileHandler:
        fileHandler.write('Enrollment ID,CN,SAN(S),Status,Expiration,Validation,Type,Contact\n')
    cpsObject = cps(access_hostname)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath,localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            #rootLogger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)
            for everyEnrollmentInfo in enrollmentsJsonContent:
                enrollmentId = everyEnrollmentInfo['enrollmentId']
                enrollmentDetails = cpsObject.getEnrollment(session, enrollmentId)
                if enrollmentDetails.status_code == 200:
                    enrollmentDetailsJson = enrollmentDetails.json()
                    with open(os.path.join('output','CPSAudit.csv'),'a') as fileHandler:
                        fileHandler.write(str(enrollmentId) + ', '+ enrollmentDetailsJson['csr']['cn'] + ', ' + str(enrollmentDetailsJson['csr']['sans']).replace(',', ' | ') + ', ' + 'Status' + ', ' + 'Expiration' + ', ' + enrollmentDetailsJson['validationType'] \
                        + ', ' + enrollmentDetailsJson['certificateType'] + ', ' + enrollmentDetailsJson['adminContact']['email'] + '\n')
                else:
                    rootLogger.info('Unable to fetch Enrollment details for enrollmentId: ' + str(enrollmentId))



#Final or common Successful exit
exit(0)
