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
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
    client_token = config['cps']['client_token']
    client_secret = config['cps']['client_secret']
    access_token = config['cps']['access_token']
    access_hostname = config['cps']['host']
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
parser.add_argument("--getDetail",help="Get detailed information about specific certificate",action="store_true")
parser.add_argument("--getStatus",help="Get current status about specific certificate",action="store_true")
parser.add_argument("--audit",help="Generate a complete audit report of all certificates",action="store_true")
parser.add_argument("--cn",help="Hostname/CommonName of certificate of interest")
parser.add_argument("--certDetails",help="Hostname/CommonName/SAN of certificate of interest")



#Additional arguments
#parser.add_argument("-verbose",help="Display detailed rule information for a specific version (only for -getDetail method with -version)", action="store_true")
#parser.add_argument("--SANList",help="Hostname/CommonName/SAN of certificate of interest")
parser.add_argument("--debug",help="Optional parameter for extra logging",action="store_true")
parser.add_argument("--listEnrollments",help="List all enrollments",action="store_true")
parser.add_argument("--general",help="To be used with --getDetail to display general details",action="store_true")
parser.add_argument("--certInfo",help="To be used with --getDetail to display Certificate information",action="store_true")
parser.add_argument("--companyInfo",help="To be used with --getDetail to display details about company",action="store_true")
parser.add_argument("--contactInfo",help="To be used with --getDetail to display contact details(Admin and Tech)",action="store_true")
args = parser.parse_args()


#Check for valid command line arguments
if not args.setup and not args.getDetail and not args.cn and not args.audit and not args.certDetails \
    and not args.getStatus and not args.listEnrollments and not args.debug:
    rootLogger.info("Use -h for help options")
    exit(-1)


def printData(title, data):
    #rootLogger.info('I was called with ' + str(len(data)))
    table = PrettyTable(title)
    for eachItem in data.keys():
        value = str(eachItem).upper() + ': ' + str(data[eachItem])
        table.add_row([value])
    rootLogger.info(table)


#Override log level if user wants to run in debug mode
#Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
if args.debug:
    rootLogger.setLevel(logging.DEBUG)


if args.setup:
    rootLogger.info('Setting up required files.... please wait')
    #Create the wrapper object to make calls
    cpsObject = cps(access_hostname)
    rootLogger.info('Processing Enrollments...')
    contractId = 'M-1O66EMG'
    enrollmentsPath = os.path.join('enrollments')
    #Delete the groups folder before we start
    if os.path.exists(enrollmentsPath):
        shutil.rmtree(enrollmentsPath)
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)
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
                    enrollmentInfo['contractId'] = contractId
                    if 'sans' in everyEnrollment['csr'] and everyEnrollment['csr']['sans'] is not None:
                        enrollmentInfo['sans'] = everyEnrollment['csr']['sans']
                    enrollmentInfo['enrollmentId'] = int(everyEnrollment['location'].split('/')[-1])
                    enrollmentOutput.append(enrollmentInfo)
            enrollmentsFile.write(json.dumps(enrollmentOutput,indent=4))
            rootLogger.info('Enrollments details are stored in ' + '"' + os.path.join(enrollmentsPath,'enrollments.json') + '"')
    else:
        rootLogger.info('Unable to list Enrollments.')
        exit(-1)


if args.getDetail:
    if not args.cn:
        rootLogger.info('Hostname/CN/SAN is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('enrollments')
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
                        printableData = {}
                        printCustom = 'No'
                        if args.general:
                            printCustom = 'Yes'
                            printableData['validation'] = enrollmentDetailsJson['validationType']
                            printableData['cerificateType'] = enrollmentDetailsJson['certificateType']
                            printableData['cA'] = 'Symantec'
                            if 'sni' in enrollmentDetailsJson['networkConfiguration'] and enrollmentDetailsJson['networkConfiguration']['sni'] is not None:
                                printableData['sniOnly'] = enrollmentDetailsJson['networkConfiguration']['sni']['dnsNames']
                            else:
                                printableData['sniOnly'] = 'Off'
                            printableData['changeManagement'] = enrollmentDetailsJson['changeManagement']
                            printableData['signatureAlgorithm'] = enrollmentDetailsJson['signatureAlgorithm']
                            printData(['General'], printableData)

                        if args.certInfo:
                            printCustom = 'Yes'
                            printableData['commonName'] = enrollmentDetailsJson['csr']['cn']
                            printableData['organization'] = enrollmentDetailsJson['org']['name']
                            printableData['unit'] = enrollmentDetailsJson['csr']['ou']
                            printableData['country'] = enrollmentDetailsJson['csr']['c']
                            printableData['state'] = enrollmentDetailsJson['csr']['st']
                            printableData['city'] = enrollmentDetailsJson['csr']['l']
                            printData(['CertInfo'], printableData)

                        if args.companyInfo:
                            printCustom = 'Yes'
                            printableData['name'] = enrollmentDetailsJson['org']['name']
                            printableData['addressLineOne'] = enrollmentDetailsJson['org']['addressLineOne']
                            printableData['addressLineTwo'] = enrollmentDetailsJson['org']['addressLineTwo']
                            printableData['city'] = enrollmentDetailsJson['org']['city']
                            printableData['region'] = enrollmentDetailsJson['org']['region']
                            printableData['postalCode'] = enrollmentDetailsJson['org']['postalCode']
                            printableData['country'] = enrollmentDetailsJson['org']['country']
                            printableData['phone'] = enrollmentDetailsJson['org']['phone']
                            printData(['CompanyInfo'], printableData)

                        if args.contactInfo:
                            printCustom = 'Yes'
                            #Admin details
                            printableData['firstName'] = enrollmentDetailsJson['adminContact']['firstName']
                            printableData['lastName'] = enrollmentDetailsJson['adminContact']['lastName']
                            printableData['phone'] = enrollmentDetailsJson['adminContact']['phone']
                            printableData['email'] = enrollmentDetailsJson['adminContact']['email']
                            #Tech details
                            printableData['techFirstName'] = enrollmentDetailsJson['techContact']['firstName']
                            printableData['techLastName'] = enrollmentDetailsJson['techContact']['lastName']
                            printableData['techPhone'] = enrollmentDetailsJson['techContact']['phone']
                            printableData['techEmail'] = enrollmentDetailsJson['techContact']['email']
                            printData(['ContactInfo'], printableData)

                        if printCustom == 'No':
                            table = PrettyTable(['TYPE','SANS', 'STATUS','ADMIN_EMAIL'])
                            if 'sans' in enrollmentDetailsJson['csr']:
                                if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                                    for eachSan in enrollmentDetailsJson['csr']['sans']:
                                        table.add_row([enrollmentDetailsJson['certificateType'],eachSan, 'ACTIVE',enrollmentDetailsJson['adminContact']['email']])
                                else:
                                    for eachSan in enrollmentDetailsJson['csr']['sans']:
                                        table.add_row([enrollmentDetailsJson['certificateType'],eachSan, 'INACTIVE'],enrollmentDetailsJson['adminContact']['email'])
                            rootLogger.info(table)
                            rootLogger.info('\n You can use --general, --certInfo, --companyInfo, --contactInfo for detailed info on each section.')
                    else:
                        rootLogger.info( 'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                        exit(-1)
        else:
            rootLogger.info('Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

if args.getStatus:
    if not args.cn:
        rootLogger.info('Hostname/CN/SAN is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('enrollments')
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

if args.listEnrollments:
    cpsObject = cps(access_hostname)
    contractId = 'M-1O66EMG'
    enrollmentsResponse = cpsObject.listEnrollments(session, contractId)
    if enrollmentsResponse.status_code == 200:
        enrollmentsJson = enrollmentsResponse.json()
        #Find number of groups using len function
        totalEnrollments = len(enrollmentsJson['enrollments'])
        rootLogger.info('Total of ' + str(totalEnrollments) + ' enrollments are found.')
        table = PrettyTable(['Common Name','Total number of SAN(s)','Enrollment ID','Validation Type','Certificate Type'])

        for everyEnrollment in enrollmentsJson['enrollments']:
            if 'csr' in everyEnrollment:
                rowData = []
                #print(json.dumps(everyEnrollment, indent = 4))
                rowData.append(everyEnrollment['csr']['cn'])
                if 'sans' in everyEnrollment['csr'] and everyEnrollment['csr']['sans'] is not None:
                    rowData.append(str(len(everyEnrollment['csr']['sans'])))
                else:
                    rowData.append('NONE')
                rowData.append(everyEnrollment['location'].split('/')[-1])
                rowData.append(everyEnrollment['validationType'])
                rowData.append(everyEnrollment['certificateType'])
            table.add_row(rowData)
        rootLogger.info(table)


if args.audit:
    enrollmentsPath = os.path.join('enrollments')
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
                certResponse = cpsObject.getCertificate(session, enrollmentId)

                if enrollmentDetails.status_code == 200 and certResponse.status_code == 200:
                    enrollmentDetailsJson = enrollmentDetails.json()
                    #print(json.dumps(enrollmentDetails.json(),indent=4))
                    cert = x509.load_pem_x509_certificate(certResponse.json()['certificate'].encode(), default_backend())
                    Status = 'UNKNOWN'
                    if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                        Status = 'ACTIVE'
                    elif 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) > 0:
                        Status = 'PENDING'
                    with open(os.path.join('output','CPSAudit.csv'),'a') as fileHandler:
                        fileHandler.write(str(enrollmentId) + ', '+ enrollmentDetailsJson['csr']['cn'] + ', ' + str(enrollmentDetailsJson['csr']['sans']).replace(',', ' | ') + ', ' + Status + ', ' + str(cert.not_valid_after) + ', ' + enrollmentDetailsJson['validationType'] \
                        + ', ' + enrollmentDetailsJson['certificateType'] + ', ' + enrollmentDetailsJson['adminContact']['email'] + '\n')
                else:
                    rootLogger.info('Unable to fetch Enrollment/Certificate details for enrollmentId: ' + str(enrollmentId))
                    rootLogger.debug('Reason: ' + json.dumps(enrollmentDetails.json(), indent=4))
                    rootLogger.debug('Reason: ' + json.dumps(certResponse.json(), indent=4))

#Final or common Successful exit
exit(0)
