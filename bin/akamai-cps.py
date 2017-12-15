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
import sys
import yaml
from prettytable import PrettyTable
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from akamai.edgegrid import EdgeGridAuth, EdgeRc
import jsonpatch
import datetime
from xlsxwriter.workbook import Workbook
import csv


PACKAGE_VERSION = "0.1.0"

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'cps.log')

# Set the format of logging in console and file separately
log_formatter = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
console_formatter = logging.Formatter("%(message)s")
root_logger = logging.getLogger()

logfile_handler = logging.FileHandler(log_file, mode='w')
logfile_handler.setFormatter(log_formatter)
root_logger.addHandler(logfile_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)
# Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
root_logger.setLevel(logging.INFO)


def init_config(edgerc_file, section):
    if not edgerc_file:
        if not os.getenv("AKAMAI_EDGERC"):
            edgerc_file = os.path.join(os.path.expanduser("~"), '.edgerc')
        else:
            edgerc_file = os.getenv("AKAMAI_EDGERC")

    if not os.access(edgerc_file, os.R_OK):
        root_logger.error("Unable to read edgerc file \"%s\"" % edgerc_file)
        exit(1)

    if not section:
        if not os.getenv("AKAMAI_EDGERC_SECTION"):
            section = "cps"
        else:
            section = os.getenv("AKAMAI_EDGERC_SECTION")

    try:
        edgerc = EdgeRc(edgerc_file)
        base_url = edgerc.get(section, 'host')

        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc, section)

        return base_url, session
    except configparser.NoSectionError:
        root_logger.error("Edgerc section \"%s\" not found" % section)
        exit(1)
    except Exception:
        root_logger.info(
            "Unknown error occurred trying to read edgerc file (%s)" %
            edgerc_file)
        exit(1)

def cli():
    prog = get_prog_name()
    if len(sys.argv) == 1:
        prog += " [command]"

    parser = argparse.ArgumentParser(
        description='Akamai CLI for CPS',
        add_help=False,
        prog=prog)
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' +
                PACKAGE_VERSION)

    subparsers = parser.add_subparsers(
        title='Commands', dest="command", metavar="")

    actions = {}

    subparsers.add_parser(
        name="help",
        help="Show available help",
        add_help=False).add_argument(
        'args',
        metavar="",
        nargs=argparse.REMAINDER)

    actions["setup"] = create_sub_command(
        subparsers,
        "setup",
        "Initial setup to download all necessary policy "
        "information")

    actions["audit"] = create_sub_command(
        subparsers, "audit", "A report of all enrollments in CSV format",
        [{"name": "outputfile", "help": "Name of the outputfile to be saved to"}])

    actions["show"] = create_sub_command(
        subparsers, "show",
        "Display details of Certificate",
        [{"name": "enrollmentId", "help": "enrollmentId of the enrollment/certificate"},
         {"name": "cn", "help": "Common Name of certificate"}],
         None)

    actions["create"] = create_sub_command(
        subparsers, "create",
        "Create a new certificate, reading input from input yaml file. "
        "(Use --file to specify "
        "name of inputfile)",
        [{"name": "force",
           "help": "No value"}],
        [{"name": "file",
          "help": "Input filename from templates folder to read certificate/enrollment details"}])

    actions["update"] = create_sub_command(
        subparsers, "update",
        "Update a certificate, reading input from input yaml file. "
        "(Optionally, use --file to specify ",
        [{"name": "force", "help": "Skip the stdout display and user confirmation"},
         {"name": "enrollmentId", "help": "enrollmentId of the enrollment/certificate"},
         {"name": "cn", "help": "Common Name of Certificate to update"}],
        [{"name": "file",
          "help": "Input filename from templates folder to read certificate/enrollment details"}])

    actions["download"] = create_sub_command(
        subparsers, "download", "Download Enrollment data in yaml format to a file",
        [{"name": "outputfile", "help": "Name of the outputfile to be saved to"},
         {"name": "enrollmentId", "help": "enrollmentId of the enrollment/certificate"},
         {"name": "cn", "help": "Common Name of certificate"}],
        [{"name": "format", "help": "Accepted values are json OR yaml"}])

    actions["cancel"] = create_sub_command(
        subparsers, "cancel", "Cancel an ongoing Enrollment",
        [{"name": "enrollmentId", "help": "enrollmentId of the enrollment/certificate"},
         {"name": "cn", "help": "Common Name of certificate"}],
         None)

    actions["status"] = create_sub_command(
        subparsers, "status", "Fetch the current Status of Enrollment/Certificate",
        [{"name": "enrollmentId", "help": "enrollmentId of the enrollment/certificate"},
         {"name": "cn", "help": "Common Name of certificate"}],
         None)

    actions["list"] = create_sub_command(
        subparsers, "list", "List all Enrollments or Certificates",
        [{"name": "showExpiration", "help": "shows expiration date of the enrollment"}],
         None)

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        return 0

    if args.command == "help":
        if len(args.args) > 0:
            if actions[args.args[0]]:
                actions[args.args[0]].print_help()
        else:
            parser.prog = get_prog_name() + " help [command]"
            parser.print_help()
        return 0

    if args.command != "setup":
        confirm_setup(args)

    return getattr(sys.modules[__name__], args.command.replace("-", "_"))(args)

def create_sub_command(
        subparsers,
        name,
        help,
        optional_arguments=None,
        required_arguments=None):
    action = subparsers.add_parser(name=name, help=help, add_help=False)

    if required_arguments:
        required = action.add_argument_group("required arguments")
        for arg in required_arguments:
            name = arg["name"]
            del arg["name"]
            required.add_argument("--" + name,
                                  required=True,
                                  **arg,
                                  )

    optional = action.add_argument_group("optional arguments")
    if optional_arguments:
        for arg in optional_arguments:
            name = arg["name"]
            del arg["name"]
            if name == 'force' or name == 'showExpiration':
                optional.add_argument(
                    "--" + name,
                    required=False,
                    **arg,
                    action="store_true")
            else:
                optional.add_argument("--" + name,
                                      required=False,
                                      **arg,
                                      )

    optional.add_argument(
        "--edgerc",
        help="Location of the credentials file [$AKAMAI_EDGERC]",
        default=os.path.join(
            os.path.expanduser("~"),
            '.edgerc'))

    optional.add_argument(
        "--section",
        help="Section of the credentials file [$AKAMAI_EDGERC_SECTION]",
        default="cps")

    optional.add_argument(
        "--debug",
        help="DEBUG mode to generate additional logs for troubleshooting",
        action="store_true")

    return action

def printData(title, data):
    root_logger.info('\n')
    title.append('Values')
    table = PrettyTable(title,padding_width=3)
    table.align = "l"
    for eachItem in data.keys():
        value = []
        value.append(str(eachItem))
        value.append(str(data[eachItem]))
        table.add_row(value)
    root_logger.info(table)

# Override log level if user wants to run in debug mode
# Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
'''if args.debug:
    root_logger.setLevel(logging.DEBUG)'''

def checkEnrollmentID(args, enrollmentsJsonContent):
    enrollmentResult = {}
    enrollmentResult['found'] = False
    enrollmentResult['enrollmentId'] = 0000
    #enrollmentId argument was NOT passed to program
    if not args.enrollmentId:
        #Check for multiple/duplicate CN presence
        enrollmentCount = 0
        for everyEnrollmentInfo in enrollmentsJsonContent:
            if everyEnrollmentInfo['cn'] == args.cn or 'sans' in everyEnrollmentInfo and args.cn in everyEnrollmentInfo['sans']:
                enrollmentCount += 1
            else:
                pass
        #Error out if multiple CNs are present
        if enrollmentCount > 1:
            root_logger.info('\nMore than 1 enrollments found for same CN. Please use --enrollmentID as input\n')
            exit(0)
        else:
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == args.cn or 'sans' in everyEnrollmentInfo and args.cn in everyEnrollmentInfo['sans']:
                    enrollmentResult['enrollmentId'] = everyEnrollmentInfo['enrollmentId']
                    enrollmentResult['cn'] = everyEnrollmentInfo['cn']
                    enrollmentResult['found'] = True
                    break
    #enrollmentId argument was passed to program
    else:
        for everyEnrollmentInfo in enrollmentsJsonContent:
            if str(everyEnrollmentInfo['enrollmentId']) == str(args.enrollmentId):
                #enrollmentId is passed as argument
                enrollmentResult['enrollmentId'] = args.enrollmentId
                enrollmentResult['cn'] = everyEnrollmentInfo['cn']
                enrollmentResult['found'] = True
                break

    return enrollmentResult

def setup(args):
    #root_logger.info('Setting up required files.... please wait')
    #root_logger.info('\nDetermining the contracts available.')
    # Create the wrapper object to make calls
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    enrollmentOutput = []

    #Fetch the available contracts
    contractIds = cpsObject.getContracts(session)
    if contractIds.status_code == 200:
        #root_logger.info(json.dumps(contractIds.json(), indent=4))
        pass
    else:
        root_logger.info('Unable to fetch contracts')
        root_logger.info(json.dumps(contractIds.json(), indent=4))
        exit(-1)

    enrollmentsPath = os.path.join('setup')
    # Delete the groups folder before we start
    if os.path.exists(enrollmentsPath):
        shutil.rmtree(enrollmentsPath)
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)

    for everyContract in contractIds.json()['contracts']['items']:
        contractId = everyContract['contractId'].split('_')[1]
        root_logger.info(
            '\nProcessing Enrollments under contract: ' + contractId)
        enrollmentsResponse = cpsObject.listEnrollments(
            session, contractId)
        if enrollmentsResponse.status_code == 200:
            with open(os.path.join(enrollmentsPath, 'enrollments.json'), 'a') as enrollmentsFile:
                enrollmentsJson = enrollmentsResponse.json()
                # Find number of groups using len function
                totalEnrollments = len(enrollmentsJson['enrollments'])
                root_logger.info(str(totalEnrollments) + ' total enrollments found.')
                if (totalEnrollments > 0):
                    for everyEnrollment in enrollmentsJson['enrollments']:
                        enrollmentInfo = {}
                        if 'csr' in everyEnrollment:
                            #print(json.dumps(everyEnrollment, indent = 4))
                            enrollmentInfo['cn'] = everyEnrollment['csr']['cn']
                            enrollmentInfo['contractId'] = contractId
                            enrollmentInfo['enrollmentId'] = int(
                                everyEnrollment['location'].split('/')[-1])
                            enrollmentOutput.append(enrollmentInfo)
                    enrollmentsFile.write(
                        json.dumps(enrollmentOutput, indent=4))
        else:
            root_logger.info(
                'Unable to list Enrollments under contract: ' + contractId)
            root_logger.debug(json.dumps(
                enrollmentsResponse.json(), indent=4))
            # Cannot exit here as there might be other contracts which might
            # have enrollments
            # exit(-1)
    root_logger.info('\nEnrollments details are stored in ' + '"' +
                     os.path.join(enrollmentsPath, 'enrollments.json') + '"\n')

def show(args):
    if not args.cn and not args.enrollmentId:
        root_logger.info('Common Name (--cn) or EnrollmentId (--enrollmentId) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)

            enrollmentResult = checkEnrollmentID(args, enrollmentsJsonContent)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            root_logger.info('Showing details of ' + cn +
                            ' with enrollmentId: ' + str(enrollmentId))


            enrollmentDetails = cpsObject.getEnrollment(
                session, enrollmentId)
            if enrollmentDetails.status_code == 200:
                enrollmentDetailsJson = enrollmentDetails.json()
                yamlData = yaml.dump(enrollmentDetailsJson)
                root_logger.info(json.dumps(enrollmentDetails.json(), indent=4))
            else:
                root_logger.info(
                    'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                'Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

def status(args):
    if not args.cn and not args.enrollmentId:
        root_logger.info('Common Name (--cn) or EnrollmentId (--enrollmentId) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)

            enrollmentResult = checkEnrollmentID(args, enrollmentsJsonContent)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            #first you have to get the enrollment
            root_logger.info('Getting enrollment for ' + cn +
                                ' with enrollmentId: ' + str(enrollmentId))

            enrollmentDetails = cpsObject.getEnrollment(
                session, enrollmentId)
            if enrollmentDetails.status_code == 200:
                enrollmentDetailsJson = enrollmentDetails.json()
                #root_logger.info(json.dumps(enrollmentDetails.json(), indent=4))
                if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                    root_logger.info(
                        'The certificate is active, there are no current pending changes.')
                elif 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) > 0:
                    #root_logger.info(json.dumps(enrollmentDetailsJson, indent=4))
                    changeId = int(
                        enrollmentDetailsJson['pendingChanges'][0].split('/')[-1])
                    root_logger.info('Getting change status for changeId: ' + str(changeId))
                    #second you have to get the pending change array, and then call get change status with the change id
                    changeStatusResponse = cpsObject.getChangeStatus(
                        session, enrollmentId, changeId)
                    root_logger.info(json.dumps(changeStatusResponse.json(), indent=4))
                    if changeStatusResponse.status_code == 200:
                        changeStatusResponseJson = changeStatusResponse.json()
                        if len(changeStatusResponseJson['allowedInput']) > 0:
                            # if there is something in allowedInput, there is something to do?
                            changeType = changeStatusResponseJson['allowedInput'][0]['type']
                            root_logger.info('-----------------------------')
                            root_logger.info('\nFound Change Type: ' + changeType)
                            if changeType == 'lets-encrypt-challenges':
                                root_logger.info('Starting lets-encrypt-challenges workflow')
                                info = changeStatusResponseJson['allowedInput'][0]['info']
                                root_logger.info('\nGetting change info for: ' + info)
                                dvChangeInfoResponse = cpsObject.getDvChangeInfo(session, info)
                                root_logger.info(json.dumps(dvChangeInfoResponse.json(), indent=4))
                                if dvChangeInfoResponse.status_code == 200:
                                    dvChangeInfoResponseJson = dvChangeInfoResponse.json()
                                    numDomains = len(dvChangeInfoResponseJson['dv'])
                                    if numDomains > 0:
                                        root_logger.info('-----------------------------')
                                        root_logger.info(
                                            'Domain challenges received back from Let\'s Encrypt.\nYou now must prove control over the domains by completing either the HTTP VALIDATION STEPS or DNS VALIDATION STEPS:.\n')
                                        root_logger.info('\nA. HTTP VALIDATION STEPS:')
                                        root_logger.info('\nLet\'s Encrypt must validate that you control each domain listed on the certificate. To prove you have control, you must configure your web server for each individual URL for each domain on the certificate to redirect traffic to Akamai. Once Akamai detects the redirect is in place, CPS informs Let\'s Encrypt that it can validate the domains by answering the challenges correctly. Within a few hours of redirecting your traffic, Let\'s Encrypt automatically validates your domains and your certificate deploys.\n')


                                        table = PrettyTable(['Domain', 'Status', 'Redirect From', 'Redirect To'])
                                        table.align="l"
                                        for everyDv in dvChangeInfoResponseJson['dv']:
                                            rowData = []
                                            rowData.append(everyDv['domain'])
                                            rowData.append(everyDv['status'])
                                            rowData.append('http://redirectFrom {fullPath}')
                                            rowData.append('http://redirectTo {redirectFullPath}')
                                            table.add_row(rowData)
                                        root_logger.info(table)


                                        root_logger.info('\nB. DNS VALIDATION STEPS:')
                                        root_logger.info('\nPlease deploy a DNS TXT record using the following domains and expected values below. After the DNS records below resolve, Let\'s Encrypt automatically validates your domain and your certificate deploys\n ')
                                        #root_logger.info('\nThe end result is: DIG TXT {fullPath} \n')
                                        #root_logger.info('\nReturn: {fullPath} 7200 IN TXT {responseBody} \n')

                                        table = PrettyTable(['Domain', 'Status', 'DNS Query', 'Expected Result'])
                                        table.align = "l"
                                        for everyDv in dvChangeInfoResponseJson['dv']:
                                            rowData = []
                                            rowData.append(everyDv['domain'])
                                            rowData.append(everyDv['status'])
                                            rowData.append('DIG TXT {fullPath}')
                                            rowData.append('{fullPath} 7200 IN TXT {responseBody}')
                                            table.add_row(rowData)
                                        root_logger.info(table)
                            else:
                                root_logger.info('Unknown Change Type')
                                exit(0)


                            '''for everyInput in changeStatusResponseJson['allowedInput']:
                                info = everyInput['info']
                                customResponse = cpsObject.customCall(session, info)
                                print('\n\n')
                                root_logger.info(json.dumps(customResponse.json(), indent=4))'''

                        '''title = ['STATUS']
                        title.append('DESCRIPTION')
                        title.append('ERROR')
                        table = PrettyTable(title)
                        if 'error' in changeStatusResponseJson and changeStatusResponseJson['error'] is not None:
                            table.add_row(changeStatusResponseJson['statusInfo']['status'], changeStatusResponseJson[
                                          'statusInfo']['description'], changeStatusResponseJson['error']['description'])
                        else:
                            # There is no error
                            table_row_data = [changeStatusResponseJson['statusInfo']['status']]
                            table_row_data.append(changeStatusResponseJson['statusInfo']['description'])
                            table_row_data.append('No Error')
                            table.add_row(table_row_data)
                        root_logger.info(table)'''
                    else:
                        root_logger.info(
                            'Unable to determine change status.')
                        exit(-1)
                else:
                    root_logger.info(
                        'Unable to determine change status.')
                    exit(-1)

            else:
                root_logger.info(
                    'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                'Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

def list(args):
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    try:
        #Fetch the contractId from setup/enrollments.json file
        enrollmentsPath = os.path.join('setup')
        for root, dirs, files in os.walk(enrollmentsPath):
            localEnrollmentsFile = 'enrollments.json'
            if localEnrollmentsFile in files:
                with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                    enrollmentsStringContent = enrollmentsFileHandler.read()
                # root_logger.info(policyStringContent)
                enrollmentsJsonContent = json.loads(enrollmentsStringContent)
                for everyEnrollmentInfo in enrollmentsJsonContent:
                    contractId = everyEnrollmentInfo['contractId']
                    break

        enrollmentsResponse = cpsObject.listEnrollments(session, contractId)
        if enrollmentsResponse.status_code == 200:
            enrollmentsJson = enrollmentsResponse.json()
            # Find number of groups using len function
            totalEnrollments = len(enrollmentsJson['enrollments'])
            root_logger.info(str(totalEnrollments) + ' total enrollments found.')
            table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)', 'Certificate Type','In-Progress','Test on Staging First', ])
            if args.showExpiration:
                table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)', 'Certificate Type','In-Progress','Test on Staging First', 'Expiration'])
                root_logger.info('\nFetching list with production expiration dates. Please wait... \n')
            table.align ="l"
            count = 0
            for everyEnrollment in enrollmentsJson['enrollments']:
                if 'csr' in everyEnrollment:
                    count = count + 1
                    rowData = []
                    #print(json.dumps(everyEnrollment, indent = 4))
                    cn = everyEnrollment['csr']['cn']
                    if args.showExpiration:
                        root_logger.info('Processing ' + str(count) + ' of ' + str(
                            totalEnrollments) + ': Common Name (CN): ' + cn)
                    if 'sans' in everyEnrollment['csr'] and everyEnrollment['csr']['sans'] is not None:
                        if (len(everyEnrollment['csr']['sans']) > 1):
                            cn = cn + ' (' + str(len(everyEnrollment['csr']['sans'])) + ')'
                    else:
                        pass
                    enrollmentId = everyEnrollment['location'].split('/')[-1]
                    rowData.append(enrollmentId)
                    rowData.append(cn)
                    certificateType = everyEnrollment['validationType']
                    if certificateType != 'third-party':
                        certificateType = everyEnrollment['validationType'] + ' ' + everyEnrollment['certificateType']
                    rowData.append(certificateType)
                    #rowData.append(everyEnrollment['certificateType'])
                    if 'pendingChanges' in everyEnrollment:
                        if len(everyEnrollment['pendingChanges']) > 0:
                            rowData.append('Yes')
                        else:
                            rowData.append('No')
                    if 'changeManagement' in everyEnrollment:
                        if everyEnrollment['changeManagement'] is True:
                            rowData.append('Yes')
                        else:
                            rowData.append('No')

                if args.showExpiration:
                    #enrollmentDetailsJson = enrollmentDetails.json()
                    # print(json.dumps(enrollmentDetails.json(),indent=4))
                    certResponse = cpsObject.getCertificate(session, enrollmentId)
                    expiration = ''
                    if certResponse.status_code == 200:
                        cert = x509.load_pem_x509_certificate(certResponse.json()['certificate'].encode(), default_backend())
                        expiration = str(cert.not_valid_after.date())
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    rowData.append(expiration)
                table.add_row(rowData)
            root_logger.info(table)
    except FileNotFoundError:
        root_logger.info('\nFilename: ' + fileName + ' is not found in templates folder. Exiting.\n')
        exit(1)

def audit(args):
    if args.outputfile:
        output_file_name = args.outputfile
    else:
        timestamp = '{:%Y%m%d_%H%M%S}'.format(datetime.datetime.now())
        output_file_name = 'CPSAudit_' + str(timestamp) + '.csv'
    enrollmentsPath = os.path.join('setup')
    if not os.path.exists('audit'):
        os.makedirs('audit')
    outputFile = os.path.join('audit', output_file_name)
    xlsxFile = outputFile.replace('.csv', '') + '.xlsx'

    with open(outputFile, 'w') as fileHandler:
        fileHandler.write(
            'Enrollment ID,Common Name (CN),SAN(S),Status,Expiration (In Production),Validation,Type,\
            Test on Staging,Admin Name, Admin Email, Admin Phone, Tech Name, Tech Email, Tech Phone, \
            Geography, Secure Network, Must-Have Ciphers, Preferred Ciphers, Disallowed TLS Versions, \
            SNI, Country, State, Organization, Organization Unit \n')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            root_logger.info('\nGenerating CPS audit file...')
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)
            enrollmentTotal = len(enrollmentsJsonContent)
            count = 0
            for everyEnrollmentInfo in enrollmentsJsonContent:
                count = count + 1
                enrollmentId = everyEnrollmentInfo['enrollmentId']
                commonName = everyEnrollmentInfo['cn']
                root_logger.info('Processing ' + str(count) + ' of ' + str(enrollmentTotal) + ': Common Name (CN): ' + commonName)
                enrollmentDetails = cpsObject.getEnrollment(
                    session, enrollmentId)


                if enrollmentDetails.status_code == 200:
                    enrollmentDetailsJson = enrollmentDetails.json()
                    # print(json.dumps(enrollmentDetails.json(),indent=4))
                    certResponse = cpsObject.getCertificate(session, enrollmentId)
                    expiration = ''
                    if certResponse.status_code == 200:
                        cert = x509.load_pem_x509_certificate(certResponse.json()['certificate'].encode(), default_backend())
                        expiration = str(cert.not_valid_after.date())
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    sanCount = len(enrollmentDetailsJson['csr']['sans'])
                    sanList = str(enrollmentDetailsJson['csr']['sans']).replace(',','').replace('[','').replace(']','').replace("'",'')
                    if sanCount <= 1:
                            sanList = ''
                    changeManagement = str(enrollmentDetailsJson['changeManagement'])
                    if changeManagement.lower() == 'true':
                        changeManagement = 'yes'
                    else:
                        changeManagement = 'no'
                    Status = 'UNKNOWN'
                    adminName = enrollmentDetailsJson['adminContact']['firstName'] + ' ' + enrollmentDetailsJson['adminContact']['lastName']
                    techName = enrollmentDetailsJson['techContact']['firstName'] + ' ' + enrollmentDetailsJson['techContact']['lastName']
                    if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                        Status = 'ACTIVE'
                    elif 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) > 0:
                        Status = 'IN-PROGRESS'

                    #root_logger.info(json.dumps(enrollmentDetailsJson, indent=4))
                    if enrollmentDetailsJson['networkConfiguration']['sni'] is not None:
                        sniInfo = ''
                        for everySan in enrollmentDetailsJson['networkConfiguration']['sni']['dnsNames']:
                            sniInfo = sniInfo + ' ' + everySan
                        sniInfo = '"' + sniInfo + '"'
                    else:
                        sniInfo = ''

                    with open(outputFile, 'a') as fileHandler:
                        fileHandler.write(str(enrollmentId) + ', ' + enrollmentDetailsJson['csr']['cn'] + ', ' + sanList + ', ' + Status + ', '
                                          + expiration + ', ' + enrollmentDetailsJson['validationType']+ ', ' + enrollmentDetailsJson['certificateType'] + ', '
                                          + changeManagement + ',' + adminName + ',' + enrollmentDetailsJson['adminContact']['email'] + ', '
                                          + enrollmentDetailsJson['adminContact']['phone']+ ', ' + techName + ','
                                          + enrollmentDetailsJson['techContact']['email'] + ', ' + enrollmentDetailsJson['techContact']['phone'] + ','
                                          + enrollmentDetailsJson['networkConfiguration']['geography'] + ',' + enrollmentDetailsJson['networkConfiguration']['secureNetwork'] + ','
                                          + enrollmentDetailsJson['networkConfiguration']['mustHaveCiphers'] + ',' + enrollmentDetailsJson['networkConfiguration']['preferredCiphers'] + ','
                                          + str(enrollmentDetailsJson['networkConfiguration']['disallowedTlsVersions']) + ',' + str(sniInfo) + ','
                                          + enrollmentDetailsJson['csr']['c'] + ',' + enrollmentDetailsJson['csr']['st'] + ','
                                          + enrollmentDetailsJson['csr']['o'] + ',' + enrollmentDetailsJson['csr']['ou'] + ','
                                          + '\n')
                else:
                    root_logger.debug(
                        'Unable to fetch Enrollment/Certificate details in production for enrollmentId: ' + str(enrollmentId))
                    root_logger.debug(
                        'Reason: ' + json.dumps(enrollmentDetails.json(), indent=4))
            root_logger.info('\nDone! Output file written here: ' + outputFile)

            # Merge CSV files into XLSX
            workbook = Workbook(os.path.join(xlsxFile))
            worksheet = workbook.add_worksheet('Certificate')
            with open(os.path.join(outputFile), 'rt', encoding='utf8') as f:
                reader = csv.reader(f)
                for r, row in enumerate(reader):
                    for c, col in enumerate(row):
                        worksheet.write(r, c, col)
            workbook.close()
            #Delete the csv file at the end
            os.remove(outputFile)

def validate(jsonContent, certType):
    if certType == 'OV-SAN':
        if jsonContent['validationType'] != 'ov':
            return 'validationType must be set to ov'
        if jsonContent['certificateType'] != 'san':
            return 'certificateType must be set to san'
        if jsonContent['ra'] != 'symantec':
            return 'ra must be set to symantec'
    return '0'

def create(args):
    force = args.force
    fileName = args.file
    filePath = os.path.join(fileName)
    try:
        #Fetch the contractId from setup/enrollments.json file
        enrollmentsPath = os.path.join('setup')
        for root, dirs, files in os.walk(enrollmentsPath):
            localEnrollmentsFile = 'enrollments.json'
            if localEnrollmentsFile in files:
                with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                    enrollmentsStringContent = enrollmentsFileHandler.read()
                # root_logger.info(policyStringContent)
                enrollmentsJsonContent = json.loads(enrollmentsStringContent)
                for everyEnrollmentInfo in enrollmentsJsonContent:
                    contractId = everyEnrollmentInfo['contractId']
                    break

        try:
            with open(filePath, mode='r') as inputFileHandler:
                fileContent = inputFileHandler.read()
        except FileNotFoundError:
            root_logger.info('Unable to find file: ' + fileName)
            exit(0)

        if filePath.endswith('.yml') or filePath.endswith('.yaml'):
            jsonFormattedContent = yaml.load(fileContent)
            updateJsonContent = json.dumps(yaml.load(fileContent), indent = 2)
            certificateContent = yaml.load(fileContent)
        elif filePath.endswith('.json'):
            jsonFormattedContent = json.loads(fileContent)
            updateJsonContent = json.dumps(jsonFormattedContent, indent = 2)
            certificateContent = jsonFormattedContent
        else:
            root_logger.info('Unable to determine the file format. Filename should end with either .json or .yml')
            exit(-1)

        if not force:
            root_logger.info('\nYou are about to create a new ' + certificateContent['ra'] + ' ' + certificateContent['validationType'] + '-' + certificateContent['certificateType'] + ' enrollment for Common Name (CN) = ' + certificateContent['csr']['cn'] +
            '\nDo you wish to continue (Y/N)?')
            decision = input()
        else:
            decision = 'y'

        if decision == 'Y' or decision == 'y':
            root_logger.info('Uploading certificate information and creating enrollment..')
            base_url, session = init_config(args.edgerc, args.section)
            cpsObject = cps(base_url)
            #Send a request to create enrollment using wrapper function
            createEnrollmentResponse = cpsObject.createEnrollment(session, contractId, data=updateJsonContent)
            if createEnrollmentResponse.status_code != 200 and createEnrollmentResponse.status_code != 202:
                root_logger.info('\nFAILED to create certificate: ')
                root_logger.info('Response Code is: '+ str(createEnrollmentResponse.status_code))
                root_logger.info(json.dumps(createEnrollmentResponse.json(), indent = 4))
            else:
                root_logger.info('Successfully created Enrollment...')
                root_logger.info('\nRunning setup to refresh local cache...\n')
                setup(args)
        else:
            root_logger.info('Exiting...')
            exit(0)
    except FileNotFoundError:
        root_logger.info('\nFilename: ' + fileName + ' is not found in templates folder. Exiting.\n')
        exit(1)
    except KeyError as missingKey:
        #This is caught if --force is not used and file is validated
        root_logger.info('\n' + str(missingKey) + ' is not found in input file and is mandatory.\n')
        root_logger.info('Error: Input yaml file does not seem valid. Please check file format.\n')

        exit(1)

def update(args):
    force = args.force
    fileName = args.file
    if not args.cn and not args.enrollmentId:
        root_logger.info('Common Name (--cn) or EnrollmentId (--enrollmentId) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)

            enrollmentResult = checkEnrollmentID(args, enrollmentsJsonContent)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            try:
                with open(os.path.join(fileName), mode='r') as inputFileHandler:
                    fileContent = inputFileHandler.read()
            except FileNotFoundError:
                root_logger.info('Unable to find file: ' + fileName)
                exit(0)

            if fileName.endswith('.yml') or fileName.endswith('.yaml'):
                jsonFormattedContent = yaml.load(fileContent)
                updateJsonContent = json.dumps(yaml.load(fileContent), indent = 2)
                certificateContent = yaml.load(fileContent)
            elif fileName.endswith('.json'):
                jsonFormattedContent = json.loads(fileContent)
                updateJsonContent = json.dumps(jsonFormattedContent, indent = 2)
                certificateContent = jsonFormattedContent
            else:
                root_logger.info('Unable to determine the file format. Filename should end with either .json or .yml')
                exit(-1)

            if not force:
                root_logger.info('\nYou are about to update enrollment id: ' + str(enrollmentId) + ' and CN: ' + cn +
                '\nDo you wish to continue (Y/N)')
                decision = input()
                if decision == 'Y' or decision == 'y':
                    #compare the data
                    '''if args.cn:
                        root_logger.info('Fetching details of ' + cn +
                                        ' with enrollmentId: ' + str(enrollmentId))
                    else:
                        root_logger.info('Fetching details of enrollmentId: ' + str(enrollmentId))
                    enrollmentDetails = cpsObject.getEnrollment(
                        session, enrollmentId)'''

                    #Commenting the enrollment fetch call to compare
                    '''if enrollmentDetails.status_code == 200:
                        enrollmentDetailsJson = enrollmentDetails.json()
                        #root_logger.info(json.dumps(enrollmentDetails.json(), indent=4))
                        #root_logger.info(diff(jsonFormattedContent, enrollmentDetailsJson))
                        listOfPatches = jsonpatch.JsonPatch.from_diff(enrollmentDetailsJson,jsonFormattedContent)
                        table = PrettyTable(['Op', 'Path', 'Value'])
                        table.align ="l"
                        for everyPatch in listOfPatches:
                            #root_logger.info(everyPatch)
                            rowData = []
                            action = everyPatch['op']
                            rowData.append(action)
                            attribute = everyPatch['path']
                            #attribute = attribute.replace('/','-->')
                            #attribute = attribute.replace('-->','',1)
                            rowData.append(attribute)
                            if 'value' in everyPatch:
                                attributeValue = everyPatch['value']
                            else:
                                attributeValue = ''
                            rowData.append(attributeValue)
                            if action != 'move':
                                if 'pendingChanges' not in attribute and 'certificateChainType' not in attribute and 'thirdParty' not in attribute\
                                and 'location' not in attribute:
                                    table.add_row(rowData)
                            #root_logger.info(str(action) + ' ' + str(attribute) + ' ' + str(attributeValue))
                        root_logger.info('\nFollowing are the differences \n')
                        root_logger.info(table)

                    else:
                        root_logger.info('Unable to fetch details of enrollmentId: ' + str(enrollmentId))
                        exit(1)'''
                else:
                    #User pressed N so just go ahead, we will exit program down below
                    pass
            #User passed --force so just go ahead by selecting Y
            else:
                decision = 'y'
            if decision == 'y' or decision == 'Y':
                root_logger.info('\nTrying to update enrollment...\n')
                updateEnrollmentResponse = cpsObject.updateEnrollment(session, enrollmentId, data=updateJsonContent)
                if updateEnrollmentResponse.status_code == 200 or updateEnrollmentResponse.status_code == 202:
                    root_logger.info('Successfully updated enrollment...')
                    root_logger.info(updateEnrollmentResponse.status_code)
                    root_logger.info(json.dumps(updateEnrollmentResponse.json(), indent=4))
                else:
                    root_logger.info('Unable to update due to the below reason:\n')
                    root_logger.info(json.dumps(updateEnrollmentResponse.json(), indent=4))
            else:
                root_logger.info('Exiting...')
                exit(0)

def cancel(args):
    if not args.cn and not args.enrollmentId:
        root_logger.info('Common Name (--cn) or EnrollmentId (--enrollmentId) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)

            enrollmentResult = checkEnrollmentID(args, enrollmentsJsonContent)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)


            root_logger.info('Trying to cancel ' + cn +
                            ' with enrollmentId: ' + str(enrollmentId))


            enrollmentDetails = cpsObject.getEnrollment(
                session, enrollmentId)
            if enrollmentDetails.status_code == 200:
                enrollmentDetailsJson = enrollmentDetails.json()
                #root_logger.info(json.dumps(enrollmentDetails.json(), indent=4))
                if 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) == 0:
                    root_logger.info(
                        'The certificate is active, there are no current pending changes.')
                elif 'pendingChanges' in enrollmentDetailsJson and len(enrollmentDetailsJson['pendingChanges']) > 0:
                    changeId = int(
                        enrollmentDetailsJson['pendingChanges'][0].split('/')[-1])
                    changeStatusResponse = cpsObject.getChangeStatus(
                        session, enrollmentId, changeId)
                    #root_logger.info(json.dumps(changeStatusResponse.json(), indent=4))
                    if changeStatusResponse.status_code == 200:
                        changeStatusResponseJson = changeStatusResponse.json()
                        title = ['STATUS']
                        title.append('DESCRIPTION')
                        title.append('ERROR')
                        table = PrettyTable(title)
                        if 'error' in changeStatusResponseJson and changeStatusResponseJson['error'] is not None:
                            table.add_row(changeStatusResponseJson['statusInfo']['status'], changeStatusResponseJson[
                                          'statusInfo']['description'], changeStatusResponseJson['error']['description'])
                        else:
                            # There is no error
                            table_row_data = [changeStatusResponseJson['statusInfo']['status']]
                            table_row_data.append(changeStatusResponseJson['statusInfo']['description'])
                            table_row_data.append('No Error')
                            table.add_row(table_row_data)
                        root_logger.info(table)

                        root_logger.info('Cancelling the request with change ID: ' + str(changeId))
                        cancelChangeResponse = cpsObject.cancelChange(session, enrollmentId, changeId)
                        if cancelChangeResponse.status_code == 200:
                            root_logger.info('Cancellation successful')
                        else:
                            root_logger.info('Cancellation is NOT successful')

                    else:
                        root_logger.info(
                            'Unable to determine change status.')
                        exit(-1)
                else:
                    root_logger.info(
                        'Unable to determine change status.')
                    exit(-1)

            else:
                root_logger.info(
                    'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                'Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)

def download(args):
    format = args.format
    if format != 'json' and format != 'yml' and format != 'yaml':
        root_logger.info('Format can either be json or yaml or yml')
        exit(-1)
    if not args.cn and not args.enrollmentId:
        root_logger.info('Common Name (--cn) or EnrollmentId (--enrollmentId) is mandatory')
        exit(-1)
    cn = args.cn

    outputFolder = format
    if args.outputfile:
        outputfile = args.outputfile
    elif args.cn:
        outputfile = cn.replace('.','_') + '.' + str(format)
    else:
        enrollmentId = args.enrollmentId
        outputfile = enrollmentId.replace('.','_') + '.' + str(format)

    if not os.path.exists(outputFolder):
        os.makedirs(outputFolder)
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        localEnrollmentsFile = 'enrollments.json'
        if localEnrollmentsFile in files:
            with open(os.path.join(enrollmentsPath, localEnrollmentsFile), mode='r') as enrollmentsFileHandler:
                enrollmentsStringContent = enrollmentsFileHandler.read()
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)

            enrollmentResult = checkEnrollmentID(args, enrollmentsJsonContent)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            root_logger.info('Downloading details of ' + cn +
                            ' with enrollmentId: ' + str(enrollmentId))


            enrollmentDetails = cpsObject.getEnrollment(
                session, enrollmentId)
            if enrollmentDetails.status_code == 200:
                if format == 'yaml' or format == 'yml':
                    enrollmentDetailsJson = enrollmentDetails.json()
                    Data = yaml.dump(enrollmentDetailsJson)
                else:
                    Data = json.dumps(enrollmentDetails.json(), indent=4)

                with open(os.path.join(outputFolder, outputfile),'w') as outputfile_handler:
                    outputfile_handler.write(Data)
                root_logger.info('\nOutput saved in ' + os.path.join(outputFolder, outputfile) + '.\n')
            else:
                root_logger.info(
                    'Status Code: ' + str(enrollmentDetails.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                '\nUnable to find enrollments.json file. Try to run setup.\n')
            exit(-1)

def confirm_setup(args):
    policies_dir = os.path.join(get_cache_dir(), 'setup')

    if not os.access(policies_dir, os.W_OK):
        print(
            "Cache not found. You must create it to continue [Y/n]:",
            end=' ')

        if str.lower(input()) == 'n':
            root_logger.info('Exiting.')
            exit(1)

        return setup(args)

    return

def get_prog_name():
    prog = os.path.basename(sys.argv[0])
    if os.getenv("AKAMAI_CLI"):
        prog = "akamai cps"
    return prog

def get_cache_dir():
    if os.getenv("AKAMAI_CLI_CACHE_DIR"):
        return os.getenv("AKAMAI_CLI_CACHE_DIR")

    return os.curdir

# Final or common Successful exit
if __name__ == '__main__':
    try:
        status = cli()
        exit(status)
    except KeyboardInterrupt:
        exit(1)
