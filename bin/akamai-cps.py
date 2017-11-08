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
        [{"name": "cn", "help": "Common Name of certificate"}])

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
        [{"name": "force", "help": "Skip the stdout display and user confirmation"}],
        [{"name": "cn", "help": "Common Name of Certificate to update"},
         {"name": "file",
          "help": "Input filename from templates folder to read certificate/enrollment details"}])

    actions["download"] = create_sub_command(
        subparsers, "download", "Download Enrollment data in yaml format to a file",
        [{"name": "format", "help": "Accepted values are json OR yaml"}],
        [{"name": "cn", "help": "Common Name of certificate"},
         {"name": "outputfile", "help": "Name of the outputfile to be saved to"}])

    actions["cancel"] = create_sub_command(
        subparsers, "cancel", "Cancel an ongoing Enrollment",
        [{"name": "cn", "help": "Common Name of certificate"}])

    actions["status"] = create_sub_command(
        subparsers, "status", "Fetch the current Status of Enrollment/Certificate",
        [{"name": "cn", "help": "Common Name of certificate"}])

    actions["list"] = create_sub_command(
        subparsers, "list", "List all Enrollments or Certificates")

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
            if name == 'force':
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


def setup(args):
    #root_logger.info('Setting up required files.... please wait')
    #root_logger.info('\nDetermining the contracts available.')
    # Create the wrapper object to make calls
    base_url, session = init_config(args.edgerc, args.section)
    cpsObject = cps(base_url)
    enrollmentOutput = []
    '''    contractIds = cpsObject.getContracts(session)
    if contractIds.status_code == 200:
        root_logger.info(json.dumps(contractIds.json(), indent=4))
    else:
        root_logger.info('Unable to fetch contracts')
        root_logger.info(json.dumps(contractIds.json(), indent=4))
        exit()'''

    contractId = '1-5C13O8'
    #contractId = 'M-1O66EMG'
    root_logger.info(
        '\nProcessing Enrollments under contract: ' + contractId)
    enrollmentsPath = os.path.join('setup')
    # Delete the groups folder before we start
    if os.path.exists(enrollmentsPath):
        shutil.rmtree(enrollmentsPath)
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)
    enrollmentsResponse = cpsObject.listEnrollments(
        session, contractId)
    if enrollmentsResponse.status_code == 200:
        with open(os.path.join(enrollmentsPath, 'enrollments.json'), 'a') as enrollmentsFile:
            enrollmentsJson = enrollmentsResponse.json()
            # Find number of groups using len function
            totalEnrollments = len(enrollmentsJson['enrollments'])
            root_logger.info(str(totalEnrollments) + ' total enrollments found.')
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
            root_logger.info('Enrollments details are stored in ' + '"' +
                            os.path.join(enrollmentsPath, 'enrollments.json') + '"')
    else:
        root_logger.info(
            'Unable to list Enrollments under contract: ' + contractId)
        root_logger.debug(json.dumps(
            enrollmentsResponse.json(), indent=4))
        # Cannot exit here as there might be other contracts which might
        # have enrollments
        # exit(-1)

def show(args):
    if not args.cn:
        root_logger.info('Hostname/CN/SAN is mandatory')
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
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    root_logger.info('Fetching details of ' + cn +
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
    if not args.cn:
        root_logger.info('Hostname/CN/SAN is mandatory')
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
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    root_logger.info('Fetching details of ' + cn +
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
                            changeStatusResponse = cpsObject.getChangeStatus(
                                session, enrollmentId, changeId)
                            root_logger.info(json.dumps(changeStatusResponse.json(), indent=4))
                            if changeStatusResponse.status_code == 200:
                                changeStatusResponseJson = changeStatusResponse.json()
                                if len(changeStatusResponseJson['allowedInput']) > 0:
                                    for everyInput in changeStatusResponseJson['allowedInput']:
                                        info = everyInput['info']
                                        customResponse = cpsObject.customCall(session, info)
                                        print('\n\n')
                                        root_logger.info(json.dumps(customResponse.json(), indent=4))

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
    #contractId = 'M-1O66EMG'
    contractId = '1-5C13O8'
    enrollmentsResponse = cpsObject.listEnrollments(session, contractId)
    if enrollmentsResponse.status_code == 200:
        enrollmentsJson = enrollmentsResponse.json()
        # Find number of groups using len function
        totalEnrollments = len(enrollmentsJson['enrollments'])
        root_logger.info(str(totalEnrollments) + ' total enrollments found.')
        table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)', 'Certificate Type','Test on Staging First', 'In-Progress'])
        table.align ="l"

        for everyEnrollment in enrollmentsJson['enrollments']:
            if 'csr' in everyEnrollment:
                rowData = []
                #print(json.dumps(everyEnrollment, indent = 4))
                cn = everyEnrollment['csr']['cn']
                if 'sans' in everyEnrollment['csr'] and everyEnrollment['csr']['sans'] is not None:
                    if (len(everyEnrollment['csr']['sans']) > 1):
                        cn = cn + ' (' + str(len(everyEnrollment['csr']['sans'])) + ')'
                else:
                    pass
                rowData.append(everyEnrollment['location'].split('/')[-1])
                rowData.append(cn)
                certificateType = everyEnrollment['validationType']
                if certificateType != 'third-party':
                    certificateType = everyEnrollment['validationType'] + ' ' + everyEnrollment['certificateType']
                rowData.append(certificateType)
                #rowData.append(everyEnrollment['certificateType'])
                if 'changeManagement' in everyEnrollment:
                    if everyEnrollment['changeManagement'] is True:
                        rowData.append('Yes')
                    else:
                        rowData.append('No')
                if 'pendingChanges' in everyEnrollment:
                    if len(everyEnrollment['pendingChanges']) > 0:
                        rowData.append('Yes')
                    else:
                        rowData.append('No')
            table.add_row(rowData)
        root_logger.info(table)

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
    with open(outputFile, 'w') as fileHandler:
        fileHandler.write(
            'Enrollment ID,Common Name (CN),SAN(S),Status,Expiration (In Production),Validation,Type,Test on Staging,Admin Name, Admin Email, Admin Phone, Tech Name, Tech Email, Tech Phone\n')
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
                        expiration = str(cert.not_valid_after)
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    sanCount = len(enrollmentDetailsJson['csr']['sans'])
                    sanList = str(enrollmentDetailsJson['csr']['sans']).replace(',', ' ')
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
                    with open(outputFile, 'a') as fileHandler:
                        fileHandler.write(str(enrollmentId) + ', ' + enrollmentDetailsJson['csr']['cn'] + ', ' + sanList + ', ' + Status + ', ' + expiration + ', ' + enrollmentDetailsJson['validationType']
                                          + ', ' + enrollmentDetailsJson['certificateType'] + ', ' + changeManagement + ',' + adminName + ',' + enrollmentDetailsJson['adminContact']['email'] + ', ' + enrollmentDetailsJson['adminContact']['phone']
                                          + ', ' + techName + ',' + enrollmentDetailsJson['techContact']['email'] + ', ' + enrollmentDetailsJson['techContact']['phone'] + '\n')
                else:
                    root_logger.debug(
                        'Unable to fetch Enrollment/Certificate details in production for enrollmentId: ' + str(enrollmentId))
                    root_logger.debug(
                        'Reason: ' + json.dumps(enrollmentDetails.json(), indent=4))
            root_logger.info('\nDone! Output file written here: ' + outputFile)
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
    filePath = os.path.join('templates',fileName)
    try:
        #Read from YAML file and load convert it to JSON.
        with open(filePath,'r') as yamlContentHandler:
            yamlContent = yamlContentHandler.read()
        certificateJsonContent = json.dumps(yaml.load(yamlContent), indent = 2)
        certificateContent = yaml.load(yamlContent)
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
            contractId = '1-5C13O8'
            #Send a request to create enrollment using wrapper function
            createEnrollmentResponse = cpsObject.createEnrollment(session, contractId, data=certificateJsonContent)
            if createEnrollmentResponse.status_code != 200 and createEnrollmentResponse.status_code != 202:
                root_logger.info('\nFAILED to create certificate: ')
                root_logger.info('Response Code is: '+ str(createEnrollmentResponse.status_code))
                root_logger.info(json.dumps(createEnrollmentResponse.json(), indent = 4))
            else:
                root_logger.info('Successfully created Enrollment...')
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
    if not args.cn:
        root_logger.info('Hostname/CN/SAN is mandatory')
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
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    root_logger.info('Fetching details of ' + cn +
                                    ' with enrollmentId: ' + str(enrollmentId))
                    with open(os.path.join('templates',fileName), mode='r') as inputFileHandler:
                        yamlContent = inputFileHandler.read()
                    jsonFormattedContent = yaml.load(yamlContent)
                    updateJsonContent = json.dumps(yaml.load(yamlContent), indent = 2)
                    certificateContent = yaml.load(yamlContent)

                    if not force:
                        root_logger.info('\nYou are about to update ' + certificateContent['ra'] +
                        ': ' + certificateContent['validationType'] + '-' + certificateContent['certificateType'] +
                        ' enrollment for\nCommon Name (CN) = ' + certificateContent['csr']['cn'] +
                        '. Do you wish to continue (Y/N)')
                        decision = input()
                        if decision == 'Y' or decision == 'y':
                            #compare the data
                            root_logger.info('Fetching details of ' + cn +
                                            ' with enrollmentId: ' + str(enrollmentId))
                            enrollmentDetails = cpsObject.getEnrollment(
                                session, enrollmentId)
                            if enrollmentDetails.status_code == 200:
                                enrollmentDetailsJson = enrollmentDetails.json()
                                #root_logger.info(json.dumps(enrollmentDetails.json(), indent=4))
                                #root_logger.info(diff(jsonFormattedContent, enrollmentDetailsJson))
                                listOfPatches = jsonpatch.JsonPatch.from_diff(jsonFormattedContent, enrollmentDetailsJson)
                                #root_logger.info(patch)
                                table = PrettyTable(['Action', 'Attribute', 'Existing Value'])
                                table.align ="l"
                                for everyPatch in listOfPatches:
                                    rowData = []
                                    action = everyPatch['op']
                                    if action == 'replace':
                                        action = 'Updated'
                                    rowData.append(action)
                                    attribute = everyPatch['path']
                                    attribute = attribute.replace('/','-->')
                                    attribute = attribute.replace('-->','',1)
                                    rowData.append(attribute)
                                    attributeValue = everyPatch['value']
                                    rowData.append(attributeValue)
                                    if action != 'move':
                                        if 'pendingChanges' not in attribute and 'certificateChainType' not in attribute and 'thirdParty' not in attribute\
                                        and 'location' not in attribute:
                                            table.add_row(rowData)
                                    #root_logger.info(str(action) + ' ' + str(attribute) + ' ' + str(attributeValue))
                                root_logger.info(table)

                            else:
                                root_logger.info('Unable to fetch details of enrollmentId: ' + str(enrollmentId))
                                exit(1)
                        else:
                            #User pressed N so just go ahead, we will exit program down below
                            pass
                    #User passed --force so just go ahead by selecting Y
                    else:
                        decision = 'y'
                    root_logger.info('\nProceeding to update the enrollment.\n')
                    if decision == 'y' or decision == 'Y':
                        updateEnrollmentResponse = cpsObject.updateEnrollment(session, enrollmentId, data=updateJsonContent)
                        if updateEnrollmentResponse.status_code == 200 or 202:
                            root_logger.info('Successfully updated the enrollment.')
                            root_logger.info(json.dumps(updateEnrollmentResponse.json(), indent=4))
                    else:
                        root_logger.info('Exiting the program')
                        exit(0)

def cancel(args):
    if not args.cn:
        root_logger.info('Hostname/CN/SAN is mandatory')
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
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    root_logger.info('Fetching details of ' + cn +
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
    outputfile = args.outputfile
    format = args.format
    if not outputfile:
        root_logger.info('Output file not specified.')
        exit(-1)
    if not args.cn:
        root_logger.info('Hostname/CN/SAN is mandatory')
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
            enrollmentsJsonContent = json.loads(enrollmentsStringContent)
            for everyEnrollmentInfo in enrollmentsJsonContent:
                if everyEnrollmentInfo['cn'] == cn or 'sans' in everyEnrollmentInfo and cn in everyEnrollmentInfo['sans']:
                    enrollmentId = everyEnrollmentInfo['enrollmentId']
                    root_logger.info('\nFetching details of ' + cn +
                                    ' with enrollmentId: ' + str(enrollmentId))
                    enrollmentDetails = cpsObject.getEnrollment(
                        session, enrollmentId)
                    if enrollmentDetails.status_code == 200:
                        if format == 'yaml':
                            enrollmentDetailsJson = enrollmentDetails.json()
                            Data = yaml.dump(enrollmentDetailsJson)
                        else:
                            Data = json.dumps(enrollmentDetails.json(), indent=4)

                        with open(os.path.join('templates', outputfile),'w') as outputfile_handler:
                            outputfile_handler.write(Data)
                        root_logger.info('\nOutput saved in ' + outputfile + ' under templates directory.\n')
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
