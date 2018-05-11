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
Initiators: vbhat@akamai.com, aetsai@akamai.com, mkilmer@akamai.com
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
        "Initial setup to download all necessary enrollment info ")

    actions["list"] = create_sub_command(
        subparsers, "list", "List all enrollments",
        [{"name": "show-expiration", "help": "shows expiration date of the enrollment"}],
        None)

    actions["retrieve-enrollment"] = create_sub_command(
        subparsers, "retrieve-enrollment",
        "Output enrollment data to json or yaml format",
        [{"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"},
         {"name": "json", "help": "Output format is json"},
         {"name": "yaml", "help": "Output format is yaml"},
         {"name": "yml", "help": "Output format is yaml"},
         {"name": "network", "help": "Deployment detail of certificate in staging or production"}],
         None)

    actions["retrieve-deployed"] = create_sub_command(
        subparsers, "retrieve-deployed",
        "Output information about certifcate deployed on network",
        [{"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"},
         {"name": "network", "help": "Deployment detail of certificate in staging or production"},
         {"name": "leaf", "help": "Get leaf certificate in PEM format"},
         {"name": "chain", "help": "Get complete certificate in PEM format"},
         {"name": "info", "help": "Get details of certificate in human readable format"}],
         None)

    actions["status"] = create_sub_command(
        subparsers, "status", "Get any current change status for an enrollment",
        [{"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"}],
        [{"name": "validation-type", "help": "Use http or dns"}])

    actions["create"] = create_sub_command(
        subparsers, "create",
        "Create a new enrollment from a yaml or json input file "
        "(Use --file to specify the filename)",
        [{"name": "force","help": "No value"},
         {"name": "contract-id", "help": "Contract ID under which Enrollment/Certificate has to be created"}],
        [{"name": "file", "help": "Input filename from templates folder to read enrollment details"}])

    actions["update"] = create_sub_command(
        subparsers, "update",
        "Update an enrollment from a yaml or json input file. "
        "(Use --file to specify the filename",
        [{"name": "force", "help": "Skip the stdout display and user confirmation"},
         {"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of Certificate to update"}],
        [{"name": "file",
          "help": "Input filename from templates folder to read enrollment details"}])

    actions["cancel"] = create_sub_command(
        subparsers, "cancel", "Cancel an existing change",
        [{"name": "force", "help": "Skip the stdout display and user confirmation"},
         {"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"}],
        None)

    actions["audit"] = create_sub_command(
        subparsers, "audit", "Generate a report in xlsx format by default. Can also use --json/csv",
        [{"name": "output-file", "help": "Name of the outputfile to be saved to"},
         {"name": "json", "help": "Output format is json"},
         {"name": "csv", "help": "Output format is csv"}])


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

    # Override log level if user wants to run in debug mode
    # Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
    if args.debug:
        root_logger.setLevel(logging.DEBUG)

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
            if name == 'force' or name == 'show-expiration' or name == 'json' \
            or name == 'yaml' or name == 'yml' or name == 'leaf' or name == 'csv' \
            or name == 'chain' or name == 'info':
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



def check_enrollment_id(args, enrollments_json_content):
    enrollmentResult = {}
    enrollmentResult['found'] = False
    enrollmentResult['enrollmentId'] = 0000
    # enrollmentId argument was NOT passed to program
    if not args.enrollment_id:
        # Check for multiple/duplicate CN presence
        enrollmentCount = 0
        for every_enrollment_info in enrollments_json_content:
            if every_enrollment_info['cn'] == args.cn or 'sans' in every_enrollment_info and args.cn in every_enrollment_info['sans']:
                enrollmentCount += 1
            else:
                pass
        # Error out if multiple CNs are present
        if enrollmentCount > 1:
            root_logger.info(
                '\nMore than 1 enrollment found for same CN. Please use --enrollment-id as input\n')
            exit(0)
        else:
            for every_enrollment_info in enrollments_json_content:
                if every_enrollment_info['cn'] == args.cn or 'sans' in every_enrollment_info and args.cn in every_enrollment_info['sans']:
                    enrollmentResult['enrollmentId'] = every_enrollment_info['enrollmentId']
                    enrollmentResult['cn'] = every_enrollment_info['cn']
                    enrollmentResult['found'] = True
                    break
    # enrollmentId argument was passed to program
    else:
        for every_enrollment_info in enrollments_json_content:
            if str(every_enrollment_info['enrollmentId']) == str(args.enrollment_id):
                # enrollmentId is passed as argument
                enrollmentResult['enrollmentId'] = args.enrollment_id
                enrollmentResult['cn'] = every_enrollment_info['cn']
                enrollmentResult['found'] = True
                break

    return enrollmentResult


def setup(args, invoker='default'):
    #root_logger.info('Setting up required files.... please wait')
    #root_logger.info('\nDetermining the contracts available.')
    # Create the wrapper object to make calls
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    enrollmentOutput = []
    contracts_path = os.path.join('setup')
    contracts_file_present = False
    contracts_json_content = []
    enrollmentsPath = os.path.join('setup')
    # Delete the groups folder before we start
    if os.path.exists(os.path.join(enrollmentsPath,'enrollments.json')):
        os.remove(os.path.join(enrollmentsPath,'enrollments.json'))
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)

    #Fetch the available contracts
    if invoker == 'default':
        root_logger.info('Trying to get contract details' +
                    ' from [cps] section of ~/.edgerc file')
    contractIds = cps_object.get_contracts(session)
    if contractIds.status_code == 200:
        #root_logger.info(json.dumps(contractIds.json(), indent=4))
        contracts = contractIds.json()
        for contractId in contracts:
            if contractId.startswith('ctr_'):
                contractId = contractId.split('_')[1]
            contracts_json_content.append(contractId)
    else:
        root_logger.info('Unable to fetch contracts')
        root_logger.info(json.dumps(contractIds.json(), indent=4))
        exit(-1)

    for contractId in contracts_json_content:
        if invoker == 'default':
            root_logger.info(
                '\nProcessing Enrollments for contract: ' + contractId)
        enrollments_response = cps_object.list_enrollments(
            session, contractId)
        if enrollments_response.status_code == 200:
            enrollments_json = enrollments_response.json()
            # Find number of groups using len function
            totalEnrollments = len(enrollments_json['enrollments'])
            if invoker == 'default':
                root_logger.info(str(totalEnrollments) +
                                 ' total enrollments found.')
            if (totalEnrollments > 0):
                for every_enrollment in enrollments_json['enrollments']:
                    enrollmentInfo = {}
                    if 'csr' in every_enrollment:
                        #print(json.dumps(every_enrollment, indent = 4))
                        enrollmentInfo['cn'] = every_enrollment['csr']['cn']
                        enrollmentInfo['contractId'] = contractId
                        enrollmentInfo['enrollmentId'] = int(
                            every_enrollment['location'].split('/')[-1])
                        enrollmentOutput.append(enrollmentInfo)

        else:
            root_logger.info(
                'Unable to find enrollments')
            root_logger.debug(json.dumps(
                enrollments_response.json(), indent=4))
            # Cannot exit here as there might be other contracts which might
            # have enrollments
            # exit(-1)
    with open(os.path.join(enrollmentsPath, 'enrollments.json'), 'a') as enrollmentsFile:
        enrollmentsFile.write(
            json.dumps(enrollmentOutput, indent=4))

    if invoker == 'default':
        root_logger.info('\nEnrollments details are stored in ' + '"' +
                         os.path.join(enrollmentsPath, 'enrollments.json') + '". \nRun \'list\' to see all enrollments.\n')


def status(args):
    validation_type = args.validation_type
    if validation_type.upper() != 'http'.upper() and validation_type.upper() != 'dns'.upper():
        root_logger.info('Please enter valid values for validation_type. (http/dns)')
        exit(-1)
    if not args.cn and not args.enrollment_id:
        root_logger.info('common Name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollments_json_content = json.loads(enrollments_string_content)

            enrollmentResult = check_enrollment_id(args, enrollments_json_content)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info(
                    'Enrollment not found. Please double check common name (CN) or enrollment-id.')
                exit(0)

            # first you have to get the enrollment
            root_logger.info('\nGetting enrollment for ' + cn +
                             ' with enrollment-id: ' + str(enrollmentId))

            enrollment_details = cps_object.get_enrollment(
                session, enrollmentId)
            if enrollment_details.status_code == 200:
                enrollment_details_json = enrollment_details.json()
                #root_logger.info(json.dumps(enrollment_details.json(), indent=4))
                if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
                    root_logger.info(
                        'The certificate is active, there are no current pending changes.')
                elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
                    #root_logger.debug(json.dumps(enrollment_details_json, indent=4))
                    changeId = int(
                        enrollment_details_json['pendingChanges'][0].split('/')[-1])
                    root_logger.info(
                        'Getting change status for changeId: ' + str(changeId))
                    # second you have to get the pending change array, and then call get change status with the change id
                    change_status_response = cps_object.get_change_status(
                        session, enrollmentId, changeId)
                    #root_logger.info(json.dumps(change_status_response.json(), indent=4))
                    if change_status_response.status_code == 200:
                        change_status_response_json = change_status_response.json()
                        if len(change_status_response_json['allowedInput']) > 0:
                            # if there is something in allowedInput, there is something to do
                            changeType = change_status_response_json['allowedInput'][0]['type']
                            # root_logger.info('-----------------------------')
                            root_logger.info(
                                'Change Type Found: ' + changeType)
                            if changeType == 'lets-encrypt-challenges':
                                info = change_status_response_json['allowedInput'][0]['info']
                                root_logger.info('\nGetting change info for: ' + info + '\n')
                                dvChangeInfoResponse = cps_object.get_dv_change_info(
                                    session, info)
                                #debug print out change info response
                                #root_logger.info(json.dumps(dvChangeInfoResponse.json(), indent=4))
                                if validation_type.upper() == 'http'.upper():
                                    if dvChangeInfoResponse.status_code == 200:
                                        dvChangeInfoResponseJson = dvChangeInfoResponse.json()
                                        numDomains = len(
                                            dvChangeInfoResponseJson['dv'])
                                        if numDomains > 0:
                                            table = PrettyTable(
                                                ['Domain', 'Status', 'Token','Expiration'])
                                            table.align = "l"
                                            for everyDv in dvChangeInfoResponseJson['dv']:
                                                #root_logger.info(json.dumps(everyDv, indent =4))
                                                rowData = []
                                                for everyChallenge in everyDv['challenges']:
                                                    if 'type' in everyChallenge and everyChallenge['type'] == 'http-01':
                                                        rowData.append(everyDv['domain'])
                                                        rowData.append(everyDv['status'])
                                                        rowData.append(everyChallenge['token'])
                                                        rowData.append(everyDv['expires'])
                                                        table.add_row(rowData)
                                            root_logger.info(table)

                                            root_logger.info('\nHTTP VALIDATION INFO:')
                                            root_logger.info('For each domain in the table that has not been validated, configure a redirect as follows:\n')
                                            root_logger.info('http://<domain>/.well-known/acme-challenge/<token> --> http://dcv.akamai.com/.well-known/acme-challenge/<token>\n')
                                elif validation_type.upper() == 'dns'.upper():
                                    if dvChangeInfoResponse.status_code == 200:
                                        dvChangeInfoResponseJson = dvChangeInfoResponse.json()
                                        numDomains = len(dvChangeInfoResponseJson['dv'])
                                        if numDomains > 0:
                                            table = PrettyTable(['Domain', 'Status', 'Token', 'Expiration'])
                                            table.align = "l"
                                            for everyDv in dvChangeInfoResponseJson['dv']:
                                                rowData = []
                                                for everyChallenge in everyDv['challenges']:
                                                    if 'type' in everyChallenge and everyChallenge['type'] == 'dns-01':
                                                        rowData.append(everyDv['domain'])
                                                        rowData.append(everyDv['status'])
                                                        rowData.append(everyChallenge['token'])
                                                        rowData.append(everyDv['expires'])
                                                        table.add_row(rowData)
                                            root_logger.info(table)

                                            root_logger.info('\nDNS VALIDATION INFO:')
                                            root_logger.info('For each domain in the table that has not been validated, configure a DNS TXT record using the specified DNS token as follows:\n')
                                            root_logger.info('DNS Query: DIG TXT _acme_challenge.<domain>')
                                            root_logger.info('Expected Result: _acme_challenge.<domain> 7200 IN TXT <token>\n')
                            else:
                                root_logger.info(
                                    'Unsupported Change Type at this time: ' + changeType)
                                exit(0)
                        else:
                            # have a change status object, but no allowed input data, try again later?
                            root_logger.info(
                                'Found pending changes, but next validation steps are not ready yet. Please check back later...')
                            if 'statusInfo' in change_status_response_json and len(change_status_response_json['statusInfo']) > 0:
                                chstatus = change_status_response_json['statusInfo']['status']
                                chdesc =  change_status_response_json['statusInfo']['description']
                                root_logger.info('\nChange Status Information:')
                                root_logger.info('Status = ' + chstatus)
                                root_logger.info('Description = ' + chdesc)
                            exit(0)
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
                    'Status Code: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                'Unable to find enrollments.json file. Try to run -setup.')
            exit(-1)


def list(args):
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    contract_id_set = set()
    try:
        #Iterate all contracts
        enrollments_response = cps_object.list_enrollments(session)
        if enrollments_response.status_code == 200:
            #Initialize the table
            table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)',
                                 'Certificate Type', '*In-Progress*', 'Test on Staging First', ])
            if args.show_expiration:
                table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)',
                                     'Certificate Type', '*In-Progress*', 'Test on Staging First', 'Expiration'])
                root_logger.info(
                    '\nFetching list with production expiration dates. Please wait... \n')
            table.align = "l"

            enrollments_json = enrollments_response.json()
            # Find number of groups using len function
            totalEnrollments = len(enrollments_json['enrollments'])
            count = 0
            for every_enrollment in enrollments_json['enrollments']:
                if 'csr' in every_enrollment:
                    count = count + 1
                    rowData = []
                    #print(json.dumps(every_enrollment, indent = 4))
                    cn = every_enrollment['csr']['cn']
                    if args.show_expiration:
                        root_logger.info('Processing ' + str(count) + ' of ' + str(
                            totalEnrollments) + ': Common Name (CN): ' + cn)
                    if 'sans' in every_enrollment['csr'] and every_enrollment['csr']['sans'] is not None:
                        if (len(every_enrollment['csr']['sans']) > 1):
                            cn = cn + \
                                ' (' + \
                                str(len(every_enrollment['csr']['sans'])) + ')'
                    else:
                        pass
                    enrollmentId = every_enrollment['location'].split('/')[-1]
                    # Checking pending changes to add star mark
                    if 'pendingChanges' in every_enrollment:
                        if len(every_enrollment['pendingChanges']) > 0:
                            rowData.append('*' + str(enrollmentId) + '*')
                        else:
                            rowData.append(enrollmentId)
                    # rowData.append(enrollmentId
                    rowData.append(cn)
                    certificateType = every_enrollment['validationType']
                    if certificateType != 'third-party':
                        certificateType = every_enrollment['validationType'] + \
                            ' ' + every_enrollment['certificateType']
                    rowData.append(certificateType)
                    # rowData.append(every_enrollment['certificateType'])
                    if 'pendingChanges' in every_enrollment:
                        if len(every_enrollment['pendingChanges']) > 0:
                            rowData.append('*Yes*')
                        else:
                            rowData.append('No')
                    if 'changeManagement' in every_enrollment:
                        if every_enrollment['changeManagement'] is True:
                            rowData.append('Yes')
                        else:
                            rowData.append('No')

                if args.show_expiration:
                    #enrollment_details_json = enrollment_details.json()
                    # print(json.dumps(enrollment_details.json(),indent=4))
                    certResponse = cps_object.get_certificate(
                        session, enrollmentId)
                    expiration = ''
                    if certResponse.status_code == 200:
                        cert = x509.load_pem_x509_certificate(
                            certResponse.json()['certificate'].encode(), default_backend())
                        expiration = str(cert.not_valid_after.date())
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    rowData.append(expiration)
                table.add_row(rowData)
            root_logger.info(table)
            root_logger.info('\n** means enrollment has existing pending changes\n')
        else:
            root_logger.info('Could not list enrollments. Please ensure you have run setup to populate the local enrollments.json file')
    except FileNotFoundError:
        root_logger.info('\nFilename: ' + fileName +
                         ' is not found in templates folder. Exiting.\n')
        exit(1)


def audit(args):
    if args.output_file:
        output_file = args.output_file
    else:
        #Default it to audit directory
        if not os.path.exists('audit'):
            os.makedirs('audit')
        timestamp = '{:%Y%m%d_%H%M%S}'.format(datetime.datetime.now())
        output_file_name = 'CPSAudit_' + str(timestamp) + '.csv'
        output_file = os.path.join('audit', output_file_name)

    enrollmentsPath = os.path.join('setup')

    xlsxFile = output_file.replace('.csv', '') + '.xlsx'
    json_file = output_file.replace('.csv', '') + '.json'
    final_json_array = []

    with open(output_file, 'w') as fileHandler:
        fileHandler.write(
            'Contract,Enrollment ID,Common Name (CN),SAN(S),Status,Expiration (In Production),Validation,Type,\
            Test on Staging,Admin Name, Admin Email, Admin Phone, Tech Name, Tech Email, Tech Phone, \
            Geography, Secure Network, Must-Have Ciphers, Preferred Ciphers, Disallowed TLS Versions, \
            SNI, Country, State, Organization, Organization Unit \n')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            root_logger.info('\nGenerating CPS audit file...')
            enrollments_json_content = json.loads(enrollments_string_content)
            enrollmentTotal = len(enrollments_json_content)
            count = 0
            for every_enrollment_info in enrollments_json_content:
                count = count + 1
                contract_id = every_enrollment_info['contractId']
                enrollmentId = every_enrollment_info['enrollmentId']
                commonName = every_enrollment_info['cn']
                root_logger.info('Processing ' + str(count) + ' of ' +
                                 str(enrollmentTotal) + ': Common Name (CN): ' + commonName)
                enrollment_details = cps_object.get_enrollment(
                    session, enrollmentId)

                if enrollment_details.status_code == 200:
                    enrollment_details_json = enrollment_details.json()

                    #Update the final json array if the output format is json. used at the end
                    enrollment_json_info = enrollment_details_json
                    enrollment_json_info['contractId'] = contract_id


                    certResponse = cps_object.get_certificate(
                        session, enrollmentId)
                    expiration = ''
                    if certResponse.status_code == 200:
                        cert = x509.load_pem_x509_certificate(
                            certResponse.json()['certificate'].encode(), default_backend())
                        expiration = str(cert.not_valid_after.date())
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    sanCount = len(enrollment_details_json['csr']['sans'])
                    sanList = str(enrollment_details_json['csr']['sans']).replace(
                        ',', '').replace('[', '').replace(']', '')
                    if sanCount <= 1:
                        sanList = ''
                    changeManagement = str(
                        enrollment_details_json['changeManagement'])
                    if changeManagement.lower() == 'true':
                        changeManagement = 'yes'
                    else:
                        changeManagement = 'no'
                    disallowedTlsVersions = str(enrollment_details_json['networkConfiguration']['disallowedTlsVersions']).replace(
                        ',', '').replace('[', '').replace(']', '')
                    Status = 'UNKNOWN'
                    adminName = enrollment_details_json['adminContact']['firstName'] + \
                        ' ' + enrollment_details_json['adminContact']['lastName']
                    techName = enrollment_details_json['techContact']['firstName'] + \
                        ' ' + enrollment_details_json['techContact']['lastName']
                    if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
                        Status = 'ACTIVE'
                    elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
                        Status = 'IN-PROGRESS'

                    #root_logger.info(json.dumps(enrollment_details_json, indent=4))
                    if enrollment_details_json['networkConfiguration']['sni'] is not None:
                        sniInfo = ''
                        for everySan in enrollment_details_json['networkConfiguration']['sni']['dnsNames']:
                            sniInfo = sniInfo + ' ' + everySan
                        sniInfo = '"' + sniInfo + '"'
                    else:
                        sniInfo = ''

                    with open(output_file, 'a') as fileHandler:
                        fileHandler.write(contract_id + ',' + str(enrollmentId) + ', ' + enrollment_details_json['csr']['cn'] + ', ' + sanList + ', ' + Status + ', '
                                          + expiration + ', ' +
                                          enrollment_details_json['validationType'] + ', ' +
                                          enrollment_details_json['certificateType'] + ', '
                                          + changeManagement + ',' + adminName + ',' +
                                          enrollment_details_json['adminContact']['email'] + ', '
                                          + enrollment_details_json['adminContact']['phone'] + ', ' + techName + ','
                                          + enrollment_details_json['techContact']['email'] + ', ' +
                                          enrollment_details_json['techContact']['phone'] + ','
                                          + enrollment_details_json['networkConfiguration']['geography'] + ',' +
                                          enrollment_details_json['networkConfiguration']['secureNetwork'] + ','
                                          + enrollment_details_json['networkConfiguration']['mustHaveCiphers'] + ',' +
                                          enrollment_details_json['networkConfiguration']['preferredCiphers'] + ','
                                          + disallowedTlsVersions +
                                          ',' + str(sniInfo) + ','
                                          + enrollment_details_json['csr']['c'] + ',' + enrollment_details_json['csr']['st'] + ','
                                          + enrollment_details_json['csr']['o'] + ',' + enrollment_details_json['csr']['ou'] + ','
                                          + '\n')
                    #if json format is of interest
                    if args.json:
                        deployment_details = cps_object.get_certificate(session, enrollmentId)
                        if deployment_details.status_code == 200:
                            enrollment_json_info['productionDeployment'] = deployment_details.json()
                        else:
                            root_logger.debug(
                                'Unable to fetch deployment/Certificate details in production for enrollment-id: ' + str(enrollmentId))
                        #Populate the final list
                        final_json_array.append(enrollment_json_info)

                else:
                    root_logger.debug(
                        'Unable to fetch Enrollment/Certificate details in production for enrollment-id: ' + str(enrollmentId))
                    root_logger.debug(
                        'Reason: ' + json.dumps(enrollment_details.json(), indent=4))

            if args.csv:
                root_logger.info('\nDone! Output file written here: ' + output_file)
            elif args.json:
                root_logger.info('\nDone! Output file written here: ' + json_file)
                with open(os.path.join(json_file), 'w') as f:
                    f.write(json.dumps(final_json_array, indent=4))
                    os.remove(output_file)
            else:
                root_logger.info('\nDone! Output file written here: ' + xlsxFile)
                # Merge CSV files into XLSX
                workbook = Workbook(os.path.join(xlsxFile))
                worksheet = workbook.add_worksheet('Certificate')
                with open(os.path.join(output_file), 'rt', encoding='utf8') as f:
                    reader = csv.reader(f)
                    for r, row in enumerate(reader):
                        for c, col in enumerate(row):
                            worksheet.write(r, c, col)
                workbook.close()
                # Delete the csv file at the end
                os.remove(output_file)


def create(args):
    force = args.force
    fileName = args.file
    filePath = os.path.join(fileName)

    try:
        if not args.contract_id:
            # Fetch the contractId from setup/enrollments.json file
            #Commenting out till papi access is resolved
            contract_id_list = set()
            enrollmentsPath = os.path.join('setup')
            for root, dirs, files in os.walk(enrollmentsPath):
                local_enrollments_file = 'enrollments.json'
                if local_enrollments_file in files:
                    with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                        enrollments_string_content = enrollmentsFileHandler.read()
                    # root_logger.info(policyStringContent)
                    enrollments_json_content = json.loads(enrollments_string_content)
                    for every_enrollment_info in enrollments_json_content:
                        contractId = every_enrollment_info['contractId']
                        contract_id_list.add(contractId)

            #Validate number of contracts
            if len(contract_id_list) > 1:
                root_logger.info('\nMultiple contracts exist, please specify' +
                                ' --contract-id to use for new enrollment\n')
                exit(0)
            else:
                #Get element from set
                contractId = contract_id_list.pop()
        else:
            contractId = args.contract_id
            if contractId.startswith('ctr_'):
                contractId = contractId.split('_')[1]


        try:
            with open(filePath, mode='r') as inputFileHandler:
                file_content = inputFileHandler.read()
        except FileNotFoundError:
            root_logger.info('Unable to find file: ' + fileName)
            exit(0)

        if filePath.endswith('.yml') or filePath.endswith('.yaml'):
            jsonFormattedContent = yaml.load(file_content)
            updateJsonContent = json.dumps(yaml.load(file_content), indent=2)
            certificateContent = yaml.load(file_content)
        elif filePath.endswith('.json'):
            jsonFormattedContent = json.loads(file_content)
            updateJsonContent = json.dumps(jsonFormattedContent, indent=2)
            certificateContent = jsonFormattedContent
        else:
            root_logger.info(
                'Unable to determine the file format. Filename should end with either .json or .yml')
            exit(-1)

        if not force:
            root_logger.info('\nYou are about to create a new ' + certificateContent['ra'] + ' ' + certificateContent['validationType'] + '-' + certificateContent['certificateType'] + ' enrollment for Common Name (CN) = ' + certificateContent['csr']['cn'] +
                             '\nDo you wish to continue (Y/N)?')
            decision = input()
        else:
            decision = 'y'

        if decision == 'Y' or decision == 'y':
            root_logger.info(
                'Uploading certificate information and creating enrollment..')
            base_url, session = init_config(args.edgerc, args.section)
            cps_object = cps(base_url)
            # Send a request to create enrollment using wrapper function
            create_enrollmentResponse = cps_object.create_enrollment(
                session, contractId, data=updateJsonContent)
            if create_enrollmentResponse.status_code != 200 and create_enrollmentResponse.status_code != 202:
                root_logger.info('\nFAILED to create certificate: ')
                root_logger.info('Response Code is: ' +
                                 str(create_enrollmentResponse.status_code))
                root_logger.info(json.dumps(
                    create_enrollmentResponse.json(), indent=4))
            else:
                root_logger.info('Successfully created Enrollment...')
                root_logger.info('\nRefreshing local cache...')
                setup(args, invoker='create')
                root_logger.info('Done...')
        else:
            root_logger.info('Exiting...')
            exit(0)
    except FileNotFoundError:
        root_logger.info('\nFilename: ' + fileName +
                         ' is not found in templates folder. Exiting.\n')
        exit(1)
    except KeyError as missingKey:
        # This is caught if --force is not used and file is validated
        root_logger.info('\n' + str(missingKey) +
                         ' is not found in input file and is mandatory.\n')
        root_logger.info(
            'Error: Input yaml file does not seem valid. Please check file format.\n')

        exit(1)


def update(args):
    force = args.force
    fileName = args.file
    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollments_json_content = json.loads(enrollments_string_content)

            enrollmentResult = check_enrollment_id(args, enrollments_json_content)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info(
                    'Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            try:
                with open(os.path.join(fileName), mode='r') as inputFileHandler:
                    file_content = inputFileHandler.read()
            except FileNotFoundError:
                root_logger.info('Unable to find file: ' + fileName)
                exit(0)

            if fileName.endswith('.yml') or fileName.endswith('.yaml'):
                jsonFormattedContent = yaml.load(file_content)
                updateJsonContent = json.dumps(
                    yaml.load(file_content), indent=2)
                certificateContent = yaml.load(file_content)
            elif fileName.endswith('.json'):
                jsonFormattedContent = json.loads(file_content)
                updateJsonContent = json.dumps(jsonFormattedContent, indent=2)
                certificateContent = jsonFormattedContent
            else:
                root_logger.info(
                    'Unable to determine the file format. Filename should end with either .json or .yml')
                exit(-1)

            if not force:
                enrollment_details = cps_object.get_enrollment(
                    session, enrollmentId)
                if enrollment_details.status_code == 200:
                    enrollment_details_json = enrollment_details.json()
                    #root_logger.info(json.dumps(enrollment_details.json(), indent=4))
                    if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
                        root_logger.info('\nYou are about to update enrollment-id: ' + str(enrollmentId) + ' and CN: ' + cn +
                                         ' \nDo you wish to continue? (Y/N)')
                        decision = input()
                    elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
                        root_logger.debug(json.dumps(
                            enrollment_details_json, indent=4))
                        root_logger.info('\nThere already exists a pending change for enrollment id: ' + str(enrollmentId) + ' and CN: ' + cn + '\nWould you like to override?' +
                                         ' This will cancel the existing change and apply the new update.' +
                                         ' \nPress (Y/N) to continue')
                        decision = input()

                # compare the data
                '''if args.cn:
                    root_logger.info('Fetching details of ' + cn +
                                    ' with enrollment-id: ' + str(enrollmentId))
                else:
                    root_logger.info('Fetching details of enrollmentId: ' + str(enrollmentId))
                enrollment_details = cps_object.get_enrollment(
                    session, enrollmentId)'''

                # Commenting the enrollment fetch call to compare
                '''if enrollment_details.status_code == 200:
                    enrollment_details_json = enrollment_details.json()
                    #root_logger.info(json.dumps(enrollment_details.json(), indent=4))
                    #root_logger.info(diff(jsonFormattedContent, enrollment_details_json))
                    listOfPatches = jsonpatch.JsonPatch.from_diff(enrollment_details_json,jsonFormattedContent)
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
                    root_logger.info(table

                else:
                    root_logger.info('Unable to fetch details of enrollmentId: ' + str(enrollmentId))
                    exit(1)'''
            # User passed --force so just go ahead by selecting Y
            else:
                # This is --force mode, so hardcode decision to y
                decision = 'y'

            if decision == 'y' or decision == 'Y':
                root_logger.info('\nTrying to update enrollment...\n')
                update_enrollmentResponse = cps_object.update_enrollment(
                    session, enrollmentId, data=updateJsonContent)
                if update_enrollmentResponse.status_code == 200:
                    root_logger.info('Update successful. This change does not require a new certificate deployment' +
                                     ' and will take effect on the next deployment. \nRun \'status\' to get updated progress details.')
                elif update_enrollmentResponse.status_code == 202:
                    root_logger.info(
                        'Update successful. This change will trigger a new certificate deployment.  \nRun \'status\' to get updated progress details.')
                else:
                    root_logger.info(
                        'Unable to update due to the below reason:\n')
                    root_logger.info(json.dumps(
                        update_enrollmentResponse.json(), indent=4))
                root_logger.debug(update_enrollmentResponse.status_code)
                root_logger.debug(json.dumps(
                    update_enrollmentResponse.json(), indent=4))
            else:
                root_logger.info('Exiting...')
                exit(0)


def cancel(args):
    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            # root_logger.info(policyStringContent)
            enrollments_json_content = json.loads(enrollments_string_content)

            enrollmentResult = check_enrollment_id(args, enrollments_json_content)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info(
                    'Enrollment not found. Please double check common name (CN) or enrollment id.')
                exit(0)

            enrollment_details = cps_object.get_enrollment(
                session, enrollmentId)
            if enrollment_details.status_code == 200:
                enrollment_details_json = enrollment_details.json()
                #root_logger.info(json.dumps(enrollment_details.json(), indent=4))
                if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
                    root_logger.info(
                        'The certificate is active, there are no current pending changes to cancel.')
                elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
                    if not args.force:
                        root_logger.info('You are about to cancel the pending change for CN: ' +
                                         cn + ' with enrollment-id: ' + str(enrollmentId) + '.\n' +
                                         'If the certificate has never been active, this will also remove the enrollment.' +
                                         ' \nDo you wish to continue? (Y/N)')
                        decision = input()
                    else:
                        decision = 'y'

                    # check the decision flag
                    if decision == 'y' or decision == 'Y':
                        changeId = int(
                            enrollment_details_json['pendingChanges'][0].split('/')[-1])
                        change_status_response = cps_object.get_change_status(
                            session, enrollmentId, changeId)
                        #root_logger.info(json.dumps(change_status_response.json(), indent=4))
                        if change_status_response.status_code == 200:
                            change_status_response_json = change_status_response.json()
                            root_logger.info(
                                '\nCancelling the request with change ID: ' + str(changeId))
                            cancel_change_response = cps_object.cancel_change(
                                session, enrollmentId, changeId)
                            if cancel_change_response.status_code == 200:
                                root_logger.info('\nCancellation successful')
                            else:
                                root_logger.info(
                                    '\nCancellation is NOT successful')
                        else:
                            root_logger.info(
                                '\nUnable to determine change status.')
                        exit(-1)
                    else:
                        root_logger.info('\nExiting...\n')
                else:
                    root_logger.info(
                        '\nUnable to determine change status.')
                    exit(-1)

            else:
                root_logger.info(
                    '\nStatus Code: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
                exit(-1)
        else:
            root_logger.info(
                '\nUnable to find enrollments.json file. Try to run -setup.')
            exit(-1)


def retrieve_enrollment(args):
    if args.json:
        format = 'json'
    elif args.yaml:
        format = 'yaml'
    elif args.yml:
        format = 'yaml'
    else:
        #Defaulting to json
        format = 'json'

    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common Name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)

    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)

    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            enrollments_json_content = json.loads(enrollments_string_content)

            enrollmentResult = check_enrollment_id(args, enrollments_json_content)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info(
                    'Enrollment not found. Please double check common name (CN) or enrollment-id.')
                exit(0)
        else:
            root_logger.info(
                '\nUnable to find enrollments.json file. Try to run setup.\n')
            exit(-1)

    cn = args.cn

    root_logger.info('Getting details for ' + cn +
                     ' with enrollment-id: ' + str(enrollmentId))

    enrollment_details = cps_object.get_enrollment(
        session, enrollmentId)
    if enrollment_details.status_code == 200:
        if format == 'yaml' or format == 'yml':
            enrollment_details_json = enrollment_details.json()
            Data = yaml.dump(enrollment_details_json,
                             default_flow_style=False)
        else:
            Data = json.dumps(enrollment_details.json(), indent=4)

        print(Data)
    else:
        root_logger.info(
            'Status Code: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
        exit(-1)


def retrieve_deployed(args):

    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common Name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)

    if not args.leaf and not args.chain and not args.info:
        root_logger.info('Please specify Either --leaf --chain or --info')
        exit(-1)

    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url)

    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            enrollments_json_content = json.loads(enrollments_string_content)

            enrollmentResult = check_enrollment_id(args, enrollments_json_content)
            if enrollmentResult['found'] is True:
                enrollmentId = enrollmentResult['enrollmentId']
                cn = enrollmentResult['cn']
            else:
                root_logger.info(
                    'Enrollment not found. Please double check common name (CN) or enrollment-id.')
                exit(0)
        else:
            root_logger.info(
                '\nUnable to find enrollments.json file. Try to run setup.\n')
            exit(-1)

    cn = args.cn

    #Default it to production network
    network = 'production'
    if args.network == 'staging':
        network = 'staging'
    root_logger.info('Fetching ' + network + ' certificate for enrollment ' + str(enrollmentId))
    deployment_details = cps_object.get_certificate(session, enrollmentId, network)
    if deployment_details.status_code == 200:
        if args.chain:
            print(deployment_details.json()['certificate'])
            print(deployment_details.json()['trustChain'])
        elif args.leaf:
            print(deployment_details.json()['certificate'])
        elif args.info:
            cert = x509.load_pem_x509_certificate(
                deployment_details.json()['certificate'].encode(), default_backend())
            expiration = str(cert.not_valid_after.date())

            for attribute in cert.subject:
                subject = attribute.value
                
            not_valid_before = str(cert.not_valid_before.date())

            for attribute in cert.issuer:
                issuer = attribute.value

            enrollment_details = cps_object.get_enrollment(
                session, enrollmentId)

            enrollment_details_json = enrollment_details.json()
            #print(json.dumps(enrollment_details_json, indent=4))
            sanList = []
            sanList = str(enrollment_details_json['csr']['sans']).replace(
                ',', '').replace('[', '').replace(']', '')
            print('\n')
            print('Network      :   ' + network)
            print('Common Name  :   ' + str(subject))
            print('Not Before   :   ' + not_valid_before)
            print('Expires      :   ' + expiration)
            print('Issuer       :   ' + str(issuer))
            print('SANs         :   ' + sanList + '\n')
        else:
            root_logger.info('Either --info OR --cert is mandatory')

    else:
        root_logger.info('Unable to fetch deployment details for enrollment-id ' + str(enrollmentId))


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
