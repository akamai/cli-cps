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
import datetime
from cpsApiWrapper import cps
from cpsApiWrapper import certificate
import argparse
import configparser
import requests
import os
import logging
import shutil
import sys
import yaml
from prettytable import PrettyTable
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from xlsxwriter.workbook import Workbook
import csv
from headers import headers


PACKAGE_VERSION = "0.1.0"

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
log_file = os.path.join('logs', 'cps.log')

# Set the format of logging in console and file separately
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_formatter = logging.Formatter("%(message)s")
root_logger = logging.getLogger()

logfile_handler = logging.FileHandler(log_file, mode='a')
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
         {"name": "cn", "help": "Common Name of certificate"},
         {"name": "validation-type", "help": "Use http or dns"}],
         None)

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

    actions["delete"] = create_sub_command(
        subparsers, "delete", "Delete an existing enrollment forever!",
        [{"name": "force", "help": "Skip the stdout display and user confirmation"},
         {"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"}],
        None)

    actions["audit"] = create_sub_command(
        subparsers, "audit", "Generate a report in csv format by default. Can also use --json/xlsx",
        [{"name": "output-file", "help": "Name of the outputfile to be saved to"},
         {"name": "json", "help": "Output format is json"},
         {"name": "xlsx", "help": "Output format is xlsx"},
         {"name": "csv", "help": "Output format is csv"}])

    actions["proceed"] = create_sub_command(
        subparsers, "proceed", "Proceed to deploy certificate",
        [{"name": "force", "help": "Skip the stdout display and user confirmation"},
         {"name": "cert-file", "help": "Signed leaf certificate (Mandatory only in case of third party cert upload)"},
         {"name": "trust-file", "help": "Signed certificate of CA (Mandatory only in case of third party cert upload)"},
         {"name": "enrollment-id", "help": "enrollment-id of the enrollment"},
         {"name": "cn", "help": "Common Name of certificate"}],
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
                                  **arg)

    optional = action.add_argument_group("optional arguments")
    if optional_arguments:
        for arg in optional_arguments:
            name = arg["name"]
            del arg["name"]
            if name == 'force' or name == 'show-expiration' or name == 'json' \
            or name == 'yaml' or name == 'yml' or name == 'leaf' or name == 'csv' or name == 'xlsx' \
            or name == 'chain' or name == 'info':
                optional.add_argument(
                    "--" + name,
                    required=False,
                    **arg,
                    action="store_true")
            else:
                optional.add_argument("--" + name,
                                      required=False,
                                      **arg)

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

    optional.add_argument(
        "--account-key",
        help="Account Switch Key",
        default="")

    return action


def check_enrollment_id(args):
    """
    Utility function that returns a sample enrollment object for later processing

    Parameters
    -----------
    args : <string>
        Should be called with --cn or --enrollment-id arguments

    Returns
    -------
    enrollmentResult : local object that stores if enrollment was found and enrollmentId
    """
    enrollmentsPath = os.path.join('setup')
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            enrollments_json_content = json.loads(enrollments_string_content)
        else:
            root_logger.info(
                'Unable to find enrollments.json file. Please run \'setup\'')
            exit(-1)

    # initialize a dummy object for return
    enrollmentResult = {}
    enrollmentResult['found'] = False
    enrollmentResult['enrollmentId'] = 0000
    # enrollment-id argument was NOT passed and trying to find enrollment-id by cn (common name)
    if not args.enrollment_id:
        # Check if duplicate CNs exists
        enrollmentCount = 0
        for every_enrollment_info in enrollments_json_content:
            if every_enrollment_info['cn'] == args.cn or 'sans' in every_enrollment_info and args.cn in every_enrollment_info['sans']:
                enrollmentCount += 1
            else:
                pass
        # Error out if multiple CNs are present
        if enrollmentCount > 1:
            print('')
            root_logger.info(
                'More than 1 enrollment found for same CN. Please use --enrollment-id as input')
            exit(0)
        else:
            for every_enrollment_info in enrollments_json_content:
                if every_enrollment_info['cn'] == args.cn or 'sans' in every_enrollment_info and args.cn in every_enrollment_info['sans']:
                    enrollmentResult['enrollmentId'] = every_enrollment_info['enrollmentId']
                    enrollmentResult['cn'] = every_enrollment_info['cn']
                    enrollmentResult['found'] = True
                    break
    # check by enrollment-id argument
    else:
        for every_enrollment_info in enrollments_json_content:
            if str(every_enrollment_info['enrollmentId']) == str(args.enrollment_id):
                # enrollment-id is passed as argument
                enrollmentResult['enrollmentId'] = args.enrollment_id
                enrollmentResult['cn'] = every_enrollment_info['cn']
                enrollmentResult['found'] = True
                break

    return enrollmentResult


def setup(args, invoker='default'):
    """
    Should be run one-time initially in order to create a local enrollment.json file that can serve as local cache for
    enrollment-id and common name (CN) look ups

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    invoker: <string>
        Description if called from another method

    Returns
    -------
    None
    """

    # Create the wrapper object to make calls
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)
    enrollmentOutput = []
    contracts_path = os.path.join('setup')
    contracts_file_present = False
    contracts_json_content = []
    enrollmentsPath = os.path.join('setup')

    # Delete the enrollments.json file before we start
    if os.path.exists(os.path.join(enrollmentsPath,'enrollments.json')):
        os.remove(os.path.join(enrollmentsPath,'enrollments.json'))
    if not os.path.exists(enrollmentsPath):
        os.makedirs(enrollmentsPath)

    # invoker == default is first time user runs setup vs. running setup after another action had been completed
    if invoker == 'default':
        root_logger.info('Trying to get contract details' +
                    ' from [' + args.section + '] section of ~/.edgerc file')
    # Fetch the available contracts.
    contractIds = cps_object.get_contracts(session)

    if contractIds.status_code == 200:
        contracts = contractIds.json()
        for contractId in contracts:
            if contractId.startswith('ctr_'):
                contractId = contractId.split('_')[1]
            contracts_json_content.append(contractId)
    else:
        root_logger.info('Invalid API Response (' + str(contractIds.status_code) + '): Unable to fetch contracts')
        root_logger.info(json.dumps(contractIds.json(), indent=4))
        exit(-1)

    # Looping through each contract to get enrollments for each contract
    for contractId in contracts_json_content:
        if invoker == 'default':
            print('')
            root_logger.info(
                'Processing Enrollments for contract: ' + contractId)
        enrollments_response = cps_object.list_enrollments(
            session, contractId)
        if enrollments_response.status_code == 200:
            enrollments_json = enrollments_response.json()
            totalEnrollments = len(enrollments_json['enrollments'])
            if invoker == 'default':
                root_logger.info(str(totalEnrollments) +
                                 ' total enrollments found.')
            # create a local enrollments json object that contains key info for each enrollment
            if (totalEnrollments > 0):
                for every_enrollment in enrollments_json['enrollments']:
                    enrollmentInfo = {}
                    if 'csr' in every_enrollment:
                        enrollmentInfo['cn'] = every_enrollment['csr']['cn']
                        enrollmentInfo['contractId'] = contractId
                        enrollmentInfo['enrollmentId'] = int(
                            every_enrollment['location'].split('/')[-1])
                        enrollmentOutput.append(enrollmentInfo)

        else:
            root_logger.info('Invalid API Response (' + str(enrollments_response.status_code) + '): Unable to get enrollments for contract')
            pass
            # Cannot exit here as there might be other contracts to loop through which might have enrollments

    # Write the created enrollments json object to the file
    with open(os.path.join(enrollmentsPath, 'enrollments.json'), 'a') as enrollmentsFile:
        enrollmentsFile.write(
            json.dumps(enrollmentOutput, indent=4))

    # If this was a first time setup, output where the enrollment.json file is located
    if invoker == 'default':
        print('')
        root_logger.info('Enrollments details are stored in ' + '"' +
                         os.path.join(enrollmentsPath, 'enrollments.json') + '".')
        print('Run \'list\' to see all enrollments.')
        print('')


def get_headers(category_name, action):
    """
    Returns a JSON object that has the appropriate headers required by the CPS API for specific calls.
    https://developer.akamai.com/api/core_features/certificate_provisioning_system/v2.html

    Parameters
    -----------
    category_name : <string>
        Input type of CPS API call that will be made
    action: <string>
        info or update based on CPS change type mapping API type

    Returns
    -------
    Local json object from headers.json with the appropriate request headers to include
    """
    try:
        headers_content = headers().data
        return headers_content['category'][category_name][action]
    except FileNotFoundError:
        root_logger.info('headers.json file is not found. Update your CPS pacakage for CLI\n')
        exit(-1)


def lets_encrypt_challenges(args,cps_object, session, change_status_response_json):
    """
    Helper method for handling Lets Encrypt status or proceed actions

    Parameters
    -----------
    args : <string>
        Default args parameter (usually either status or proceed action)
    cps_object: <object>
        Local CPS Object that has relevant http response
    session : <object
        An Edgegrid Auth (Akamai) object
    change_status_response_json : <object>
        JSON response from main CPS API get change status call for selected enrollment
    Returns
    -------
    None
    """
    # If proceed action
    if args.command == 'proceed':
        print('')
        root_logger.info('There is no manual \'proceed\' action for Lets Encrypt Challenges.')
        root_logger.info('Run \'status\' to view either the http or dns tokens to be configured.')
        root_logger.info('After validation steps are configured, CPS will process the next steps automatically after some time.')
        print('')
        exit(0)
    # Else must be status action
    if not args.validation_type:
        print('')
        root_logger.info('Lets Encrypt Certificate Found')
        print('')
        root_logger.info('Please specify --validation-type http or --validation-type dns for more details')
        print('')
        exit(0)

    # Require user to specify http or dns tokens to output for user validation setup
    validation_type = args.validation_type
    if args.validation_type.upper() != 'http'.upper() and args.validation_type.upper() != 'dns'.upper():
        root_logger.info('Please enter valid values for --validation-type (either http or dns)')
        exit(-1)

    # Display the Lets Encrypt details
    print('')
    print('LETS ENCRYPT CHALLENGE DETAILS:')
    info = change_status_response_json['allowedInput'][0]['info']
    dvChangeInfoResponse = cps_object.get_dv_change_info(
        session, info)

    # Display HTTP Tokens
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
    # Else Display DNS Tokens
    elif validation_type.upper() == 'dns'.upper():
        if dvChangeInfoResponse.status_code == 200:
            dvChangeInfoResponseJson = dvChangeInfoResponse.json()
            numDomains = len(dvChangeInfoResponseJson['dv'])
            if numDomains > 0:
                table = PrettyTable(['Domain', 'Status', 'Response Body', 'Expiration'])
                table.align = "l"
                for everyDv in dvChangeInfoResponseJson['dv']:
                    rowData = []
                    for everyChallenge in everyDv['challenges']:
                        if 'type' in everyChallenge and everyChallenge['type'] == 'dns-01':
                            rowData.append(everyDv['domain'])
                            rowData.append(everyDv['status'])
                            rowData.append(everyChallenge['responseBody'])
                            rowData.append(everyDv['expires'])
                            table.add_row(rowData)
                print(table)

                print('')
                print('DNS VALIDATION INFO:')
                print('For each domain in the table that has not been validated, configure a DNS TXT record using the specified DNS response body as follows:\n')
                print('DNS Query: dig TXT _acme-challenge.<domain')
                print('Expected Result: _acme-challenge.<domain> 7200 IN TXT <response body>')
                print('')


    # Display generic state/status/description CPS information for help for verifying status
    print('')
    root_logger.info('CPS STATUS:')
    root_logger.info('Current State = ' + change_status_response_json['statusInfo']['state'])
    root_logger.info('Current Status = ' + change_status_response_json['statusInfo']['status'])
    root_logger.info('Description = ' + change_status_response_json['statusInfo']['description'])
    print('')


def third_party_challenges(args,cps_object, session, change_status_response_json, allowed_inputdata):
    """
    Helper method for handling Third party status or proceed actions

    Parameters
    -----------
    args : <string>
        Default args parameter (usually either status or proceed action)
    cps_object: <object>
        Local CPS Object that has relevant http response
    session : <object
        An Edgegrid Auth (Akamai) object
    change_status_response_json : <json_object>
        JSON response from main CPS API get change status call for selected enrollment
    allowed_inputdata : <json_object>
        The selected allowedInput snippet from change_status_response_json
    Returns
    -------
    None
    """
    status = change_status_response_json['statusInfo']['status']
    # if csr is ready
    if status == 'wait-upload-third-party':
        if args.command == 'status':
            root_logger.info('')
            root_logger.info('3RD PARTY CERTIFICATE DETAILS:')
            info_endpoint = allowed_inputdata['info']
            root_logger.debug('Getting change info for: ' + info_endpoint)
            headers = get_headers('third-party-csr', action='info')
            changeInfoResponse = cps_object.custom_get_call(session, headers, endpoint=info_endpoint)


            root_logger.info('Below is the CSR. Please get it signed by your desired certificate authority and then run \'proceed\' to upload.')
            root_logger.info('')
            print(str(changeInfoResponse.json()['csr']))
            root_logger.info('')

        elif args.command == 'proceed':
            # for now --cert-file and --trust-file arguments are mandatory
            if not args.cert_file:
                root_logger.info('--cert-file is mandatory for thirdParty cartificate type')
                exit(-1)
            if not args.trust_file:
                root_logger.info('--trust-file is mandatory for thirdParty cartificate type')
                exit(-1)

            try:
                with open(args.cert_file,'r') as certificare_file_handler:
                    certificate_content = certificare_file_handler.read()
                with open(args.trust_file,'r') as trust_file_handler:
                    trust_content = trust_file_handler.read()
            except (FileNotFoundError, Exception) as e:
                root_logger.info(e)
                exit(-1)

            cert_object = certificate(certificate_content)
            cert_and_trust = {}
            cert_and_trust['certificate'] = certificate_content
            cert_and_trust['trustChain'] = trust_content

            certificate_content_str = json.dumps(cert_and_trust)
            update_endpoint = allowed_inputdata['update']
            headers = get_headers("third-party-csr", "update")
            root_logger.info('Trying to upload 3rd party certificate information...')
            print('')
            root_logger.debug("3rd Party POST Upload CSR Body: " + certificate_content_str)
            uploadResponse = cps_object.custom_post_call(session, headers, update_endpoint, data=certificate_content_str)

            if uploadResponse.status_code == 200:
                root_logger.info('Successfully uploaded the certificate!\n')
                root_logger.info('Please run \'status\' for current progress and next steps.\n')
                root_logger.debug(json.dumps(uploadResponse.json(), indent =4))
            else:
                root_logger.info('Invalid API Response (' + str(uploadResponse.status_code) + '): Error with uploading certificate\n')
                root_logger.info(json.dumps(uploadResponse.json(), indent =4))
    else:
        #3rd Party certificate type, but no action to be taken. Just output basic info.
        print('')
        root_logger.info('Current State = ' + change_status_response_json['statusInfo']['state'])
        root_logger.info('Current Status = ' + change_status_response_json['statusInfo']['status'])
        root_logger.info('Description = ' + change_status_response_json['statusInfo']['description'] + '\n')


def change_management(args,cps_object, session, change_status_response_json, allowed_inputdata, validation_type):
    """
    Helper method for handling Change Management status or proceed actions

    Parameters
    -----------
    args : <string>
        Default args parameter (usually either status or proceed action)
    cps_object: <object>
        Local CPS Object that has relevant http response
    session : <object
        An Edgegrid Auth (Akamai) object
    change_status_response_json : <json_object>
        JSON response from main CPS API get change status call for selected enrollment
    allowed_inputdata : <json_object>
        The selected allowedInput snippet from change_status_response_json
    validation_type : <string>
        String contaning the value of validation type
    Returns
    -------
    None
    """
    status = change_status_response_json['statusInfo']['status']
    # certificate is waiting user input to move forward
    if status == 'wait-ack-change-management':
        endpoint = allowed_inputdata['info']
        headers = get_headers("change-management-info", "info")
        changeInfoResponse = cps_object.custom_get_call(session, headers, endpoint)
        if changeInfoResponse.status_code != 200:
            root_logger.info('Invalid API Response (' + str(changeInfoResponse.status_code) + '): Unable to fetch change management information\n')
            root_logger.info(json.dumps(changeInfoResponse.json(), indent=4))
            exit(-1)


        # show status details
        if args.command == 'status':
            print('')
            print('STATUS: Waiting for someone to acknowledge change management (please review details below)')
            # Get the certificate details from the pending change info state and create a certificate object
            if changeInfoResponse.json()['pendingState']['pendingCertificate'] is not None:
                leaf_cert = changeInfoResponse.json()['pendingState']['pendingCertificate']['fullCertificate']
                certificate_details = certificate(leaf_cert)
                subject = certificate_details.subject
                cert_type = str(changeInfoResponse.json()['pendingState']['pendingCertificate']['certificateType'])

            # Display relevant information about the change
            print('')
            print('CERTIFICATE INFORMATION:')
            print('Validation Type   :   ' + validation_type)
            if changeInfoResponse.json()['pendingState']['pendingCertificate'] is not None:
                print('Certificate Type  :   ' + cert_type)
                print('Common Name (CN)  :   ' + subject)
                if hasattr(certificate_details, 'sanList'):
                    print('SAN Domains       :   ' + str(certificate_details.sanList))
                else:
                    print('SAN Domains       :   \n')
                print('Not Before        :   ' + str(certificate_details.not_valid_before))
                print('Not After         :   ' + str(certificate_details.expiration))

            sniOnly = 'Off'
            if changeInfoResponse.json()['pendingState']['pendingNetworkConfiguration']['sni'] is not None:
                sniOnly = 'On'
            print('')
            print('DEPLOYMENT INFORMATION:')
            networkType = 'Enhanced TLS (Excludes China & Russia)'
            if changeInfoResponse.json()['pendingState']['pendingNetworkConfiguration']['networkType'] is not None:
                networkType = changeInfoResponse.json()['pendingState']['pendingNetworkConfiguration']['networkType']
            print('Network Type      :   ' + networkType)
            print('Must Have Ciphers :   ' + changeInfoResponse.json()['pendingState']['pendingNetworkConfiguration']['mustHaveCiphers'])
            print('Preferred Ciphers :   ' + changeInfoResponse.json()['pendingState']['pendingNetworkConfiguration']['preferredCiphers'])
            print('SNI-Only          :   ' + sniOnly)

            print('')
            root_logger.info("Please run 'proceed --cn <common_name>' to approve and deploy to production or run 'cancel --cn <common_name>' to reject change")
            print('')

        elif args.command == 'proceed':
            # Get the hash value from the validationResultHash field necessary to acknowledge the change
            hash_value = ''
            if changeInfoResponse.json()['validationResultHash'] is not None:
                hash_value = changeInfoResponse.json()['validationResultHash']

            endpoint = allowed_inputdata['update']
            # Create the POST acknowledgement body necessary for the request
            ack_body = """
            {
                "acknowledgement": "acknowledge",
                "hash": "%s"
            }
            """ % (hash_value)
            headers = get_headers("change-management-info", "update")
            root_logger.info('\nTrying to acknowledge change...')
            post_call_response = cps_object.custom_post_call(session, headers, endpoint, data=ack_body)
            if post_call_response.status_code == 200:
                print('')
                root_logger.info('Successfully Acknowledged!  However, it may take some time for CPS to reflect this acknowledgement.  Please be patient.')
                print('')
                root_logger.info('You may run \'status\' to see when the acknowledgement has gone through.')
                print('')
                root_logger.debug(post_call_response.json())
            else:
                root_logger.info('Invalid API Response Code (' + str(post_call_response.status_code) + '): there was a problem in acknowledgement.  Please try again or contact your Akamai representative.\n')
                root_logger.info(json.dumps(post_call_response.json(), indent=4))
                exit(-1)
    else:
        root_logger.info('Unknown Status for Change Management: ' + status)
        exit()


def post_verification(args,cps_object, session, change_status_response_json, allowed_inputdata):
    """
    Helper method for handling Post Verification of status or proceed actions

    Parameters
    -----------
    args : <string>
        Default args parameter (usually either status or proceed action)
    cps_object: <object>
        Local CPS Object that has relevant http response
    session : <object
        An Edgegrid Auth (Akamai) object
    change_status_response_json : <json_object>
        JSON response from main CPS API get change status call for selected enrollment
    allowed_inputdata : <json_object>
        The selected allowedInput snippet from change_status_response_json
    Returns
    -------
    None
    """
    status = change_status_response_json['statusInfo']['status']
    # status where we have verification warnings
    if status == 'wait-review-cert-warning' or status == 'wait-review-third-party-cert':
        if args.command == 'status':
            # Display the verification warnings
            print('')
            root_logger.info('POST VERIFICATION WARNING DETAILS:')
            endpoint = allowed_inputdata['info']
            headers = get_headers("post-verification-warnings", "info")
            changeInfoResponse = cps_object.custom_get_call(session, headers, endpoint)

            if changeInfoResponse.status_code == 200:
                print('')
                root_logger.info(changeInfoResponse.json()['warnings'])
                print('')
                root_logger.info("Please run 'proceed --cn <common_name>' to acknowledge warnings or run 'cancel --cn <common_name>' to reject change")
                print('')
            else:
                root_logger.info('Invalid API Response (' + str(changeInfoResponse.status_code) + '): Unable to get post verification details. Please try again or contact an Akamai representative.')
                print(json.dumps(changeInfoResponse.json(), indent=4))
                exit(-1)
        elif args.command == 'proceed':
            endpoint = allowed_inputdata['update']
            # Create the acknowledgement body, in this case is fixed text
            ack_body = """
            {
                "acknowledgement": "acknowledge"
            }
            """
            headers = get_headers("post-verification-warnings", "update")
            root_logger.info('Acknowledging the post-verification warnings...\n')
            post_call_response = cps_object.custom_post_call(session, headers, endpoint, data=ack_body)
            if post_call_response.status_code == 200:
                root_logger.info('Successfully Acknowledged!  However, it may take some time for CPS to reflect this acknowledgement.  Please be patient.')
                print('\n')
                root_logger.info('You may run \'status\' to see when the acknowledgement has gone through.')
                print('')
                root_logger.debug(post_call_response.json())
            else:
                root_logger.info('Invalid API Response Code (' + str(post_call_response.status_code) + '): There was a problem in acknowledgement.  Please try again or contact your Akamai representative\n')
                root_logger.info(json.dumps(post_call_response.json(), indent=4))
                exit(-1)
    else:
        # Not sure how we would get here, shouldn't happen?
        root_logger.info('Unknown Error: Unknown Status for Post Verification')
        print('')
        exit(-1)


def get_status(session, cps_object, enrollmentId, cn):
    """
    Helper method to check if pending changes exist for a certificate or not

    Parameters
    -----------
    session : <object
        An Edgegrid Auth (Akamai) object
    cps_object: <object>
        Local CPS Object that has relevant http response
    enrollmentId : <int>
        Enrollment Id of certificate/Enrollment
    cn : <String>
        Common name of Enrollment
    Returns
    -------
    change_status_response : <Object>
        JSON object containing change or current status information
    """
    # first, get the enrollment
    print('')
    root_logger.info('Getting enrollment for ' + cn +
                     ' with enrollment-id: ' + str(enrollmentId))

    enrollment_details = cps_object.get_enrollment(session, enrollmentId)
    if enrollment_details.status_code == 200:
        enrollment_details_json = enrollment_details.json()
        root_logger.debug(json.dumps(enrollment_details_json, indent=4))
        if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
            root_logger.info('The certificate is active, there are no current pending changes.')
            exit(0)
        # if there is a pendingChanges object in the response, there is something to do
        elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
            changeId = int(
                enrollment_details_json['pendingChanges'][0].split('/')[-1])
            root_logger.info('Getting change status for changeId: ' + str(changeId))
            # second you have to get the pending change array, and then call get change status with the change id
            change_status_response = cps_object.get_change_status(session, enrollmentId, changeId)
            root_logger.debug(json.dumps(change_status_response.json(), indent=4))
            return change_status_response
        else:
            root_logger.info('Unknown Error: Unable to determine if any pending changes.  Please try again or contact an Akamai representative.')
            exit(-1)
    else:
        root_logger.info('Invalid API Response (' + str(enrollment_details.status_code) + '): Unable to get enrollment details.  Please try again contact an Akamai representative.')
        exit(-1)


def status(args):
    """
    Main status action for reviewing current status of a certificate.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually --cn or --enrollment-id of relevant certificate)
    Returns
    -------
    None
    """
    if not args.cn and not args.enrollment_id:
        root_logger.info('common Name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    enrollmentsPath = os.path.join('setup')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    # check local setup file to find enrollmentId necessary for CPS API calls
    enrollmentResult = check_enrollment_id(args)
    if enrollmentResult['found'] is True:
        enrollmentId = enrollmentResult['enrollmentId']
        cn = enrollmentResult['cn']
    else:
        root_logger.info('Enrollment not found. Please double check common name (CN) or enrollment-id.')
        exit(0)

    enrollment_details = cps_object.get_enrollment(session, enrollmentId)
    root_logger.debug(json.dumps(enrollment_details.json(),indent=4))
    if enrollment_details.status_code != 200:
        root_logger.info('Unable to fetch enrollment details')
        root_logger.info(json.dumps(enrollment_details.json(),indent=4))
        exit(-1)

    validation_type = str(enrollment_details.json()['validationType'])
    # Get the actual change status information
    change_status_response = get_status(session, cps_object, enrollmentId, cn)

    if change_status_response.status_code == 200:
        change_status_response_json = change_status_response.json()
        root_logger.debug(json.dumps(change_status_response.json(), indent=4))
        # if error state, nothing user can do, probably have to cancel and start over
        if change_status_response_json['statusInfo']['state'] == 'error':
            if 'error' in change_status_response_json['statusInfo'] and len(change_status_response_json['statusInfo']['error']) > 0:
                errorcode = change_status_response_json['statusInfo']['error']['code']
                errordesc =  change_status_response_json['statusInfo']['error']['description']
                print('')
                root_logger.info('Current State = error')
                root_logger.info('Error Code = ' + errorcode)
                root_logger.info('Error Description = ' + errordesc)
            print('')
            root_logger.info('ERROR: There is an error and cannot proceed. Please cancel and try again or contact an Akamai representative.')
        # if there is something in allowedInput, there is something to do
        # it is possible for multiple to exist, so process the first one where requiredToProceed is true
        elif len(change_status_response_json['allowedInput']) > 0:
            #Variable to keep track of requiredToProceed
            selectedIndex = 0
            counter = 0
            for allowed_inputdata in change_status_response_json['allowedInput']:
                if allowed_inputdata['requiredToProceed'] is True:
                    selectedIndex = counter
                    break
                else:
                    counter += 1

            sel_inputdata = change_status_response_json['allowedInput'][selectedIndex]
            changeType = sel_inputdata['type']
            # take different action based on the selected change input data
            if changeType == 'lets-encrypt-challenges':
                lets_encrypt_challenges(args, cps_object, session, change_status_response_json)
            elif changeType == 'third-party-certificate':
                third_party_challenges(args, cps_object, session, change_status_response_json, sel_inputdata)
            elif changeType == 'change-management':
                change_management(args, cps_object, session, change_status_response_json, sel_inputdata, \
                                    validation_type)
            elif changeType == 'post-verification-warnings-acknowledgement':
                post_verification(args, cps_object, session, change_status_response_json, \
                                                        sel_inputdata)
            else:
                print('')
                root_logger.info(
                    'Unsupported Change Type at this time: ' + changeType)
                exit(0)
            root_logger.info('If you just submitted a recent change update (such as an acknowledgement) and do not see it reflected yet, please note it may take some time for the status to update.\n')

        # else not sure how to handle these steps yet, just output basic info
        else:
            if 'statusInfo' in change_status_response_json and len(change_status_response_json['statusInfo']) > 0:
                chstate = change_status_response_json['statusInfo']['state']
                chstatus = change_status_response_json['statusInfo']['status']
                chdesc =  change_status_response_json['statusInfo']['description']
                print('')
                root_logger.info('Current State = ' + chstate)
                root_logger.info('Current Status = ' + chstatus)
                root_logger.info('Description = ' + chdesc)
                print('')
                root_logger.info('Changes are in-progress and any user input steps are not required at this time or not ready yet. Please check back later...')
                print('')
            exit(0)
    else:
        root_logger.info('Invalid API Response (' + change_status_response.status_code + '): Unable to determine change status details. Please try again or contact an Akamai representative.')
        exit(-1)


def proceed(args):
    """
    Main proceed action to acknowledge or provide user input to move forward with the certificate.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
    #Call existing status method
    status(args)


def list(args):
    """
    Method for handling list action. This method is responsible to list/display all enrollments.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)
    contract_id_set = set()
    try:
        # Iterate through all contracts
        enrollments_response = cps_object.list_enrollments(session)
        if enrollments_response.status_code == 200:
            # Initialize the table
            table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)',
                                 'Certificate Type', '*In-Progress*', 'Test on Staging First', ])
            if args.show_expiration:
                table = PrettyTable(['Enrollment ID', 'Common Name (SAN Count)',
                                     'Certificate Type', '*In-Progress*', 'Test on Staging First', 'Expiration'])
                print('')
                root_logger.info(
                    'Fetching list with production expiration dates. Please wait...')
                print('')
            table.align = "l"

            enrollments_json = enrollments_response.json()
            # Find number of groups using len function
            totalEnrollments = len(enrollments_json['enrollments'])
            count = 0
            for every_enrollment in enrollments_json['enrollments']:
                if 'csr' in every_enrollment:
                    count = count + 1
                    rowData = []
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
                    # Add asterisks if pending change exists for that certificate
                    if 'pendingChanges' in every_enrollment:
                        if len(every_enrollment['pendingChanges']) > 0:
                            rowData.append('*' + str(enrollmentId) + '*')
                        else:
                            rowData.append(enrollmentId)
                    rowData.append(cn)
                    certificateType = every_enrollment['validationType']
                    if certificateType != 'third-party':
                        certificateType = every_enrollment['validationType'] + \
                            ' ' + every_enrollment['certificateType']
                    rowData.append(certificateType)
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
                    # if showing expiriation date, need to get it from the certificate itself
                    certResponse = cps_object.get_certificate(
                        session, enrollmentId)
                    expiration = ''
                    if certResponse.status_code == 200:
                        certificate_details = certificate(certResponse.json()['certificate'])
                        expiration = certificate_details.expiration
                    else:
                        root_logger.debug(
                            'Reason: ' + json.dumps(certResponse.json(), indent=4))
                    rowData.append(expiration)
                table.add_row(rowData)
            print(table)
            print('')
            print('** means enrollment has existing pending changes')
            print('')
        else:
            root_logger.info('Invalid API Response (' + str(enrollments_response.status_code) + '): Could not list enrollments. Please ensure you have run \'setup\' to populate the local enrollments.json file')
    except FileNotFoundError:
        print('')
        root_logger.info('Filename: ' + fileName +
                         ' is not found in templates folder. Exiting...')
        print('')
        exit(1)


def audit(args):
    """
    Method for handling audit action. This method generates an audit report of the account or
    all enrollments. The default output format is csv, and it is configurable to xlsx or json

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
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

    xlsxFile = output_file.replace('.csv', '').replace('.xlsx', '').replace('.xls', '') + '.xlsx'
    json_file = output_file.replace('.csv', '').replace('.json', '') + '.json'
    final_json_array = []

    with open(output_file, 'w') as fileHandler:
        fileHandler.write(
            'Contract,Enrollment ID,Common Name (CN),SAN(S),Status,Expiration (In Production),Validation,Type,\
            Test on Staging,Admin Name, Admin Email, Admin Phone, Tech Name, Tech Email, Tech Phone, \
            Geography, Secure Network, Must-Have Ciphers, Preferred Ciphers, Disallowed TLS Versions, \
            SNI, Country, State, Organization, Organization Unit \n')
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)
    for root, dirs, files in os.walk(enrollmentsPath):
        local_enrollments_file = 'enrollments.json'
        if local_enrollments_file in files:
            with open(os.path.join(enrollmentsPath, local_enrollments_file), mode='r') as enrollmentsFileHandler:
                enrollments_string_content = enrollmentsFileHandler.read()
            print('')
            root_logger.info('Generating CPS audit file...')
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
                        certificate_details = certificate(certResponse.json()['certificate'])
                        expiration = certificate_details.expiration
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
                    adminName = str(enrollment_details_json['adminContact']['firstName']) + \
                        ' ' + str(enrollment_details_json['adminContact']['lastName'])
                    techName = str(enrollment_details_json['techContact']['firstName']) + \
                        ' ' + str(enrollment_details_json['techContact']['lastName'])
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
                                          str(enrollment_details_json['adminContact']['email']) + ', '
                                          + str(enrollment_details_json['adminContact']['phone']) + ', ' + techName + ','
                                          + str(enrollment_details_json['techContact']['email']) + ', ' +
                                          str(enrollment_details_json['techContact']['phone']) + ','
                                          + str(enrollment_details_json['networkConfiguration']['geography']) + ',' +
                                          str(enrollment_details_json['networkConfiguration']['secureNetwork']) + ','
                                          + str(enrollment_details_json['networkConfiguration']['mustHaveCiphers']) + ',' +
                                          str(enrollment_details_json['networkConfiguration']['preferredCiphers']) + ','
                                          + disallowedTlsVersions +
                                          ',' + str(sniInfo) + ','
                                          + str(enrollment_details_json['csr']['c']) + ',' + str(enrollment_details_json['csr']['st']) + ','
                                          + str(enrollment_details_json['csr']['o']) + ',' + str(enrollment_details_json['csr']['ou']) + ','
                                          + '\n')
                    #if json format is of interest
                    if args.json:
                        deployment_details = cps_object.get_certificate(session, enrollmentId)
                        if deployment_details.status_code == 200:
                            enrollment_json_info['productionDeployment'] = deployment_details.json()
                        else:
                            root_logger.debug(
                                'Invalid API Response (' + str(deployment_details.status_code) + '): Unable to fetch deployment/Certificate details in production for enrollment-id: ' + str(enrollmentId))
                        #Populate the final list
                        final_json_array.append(enrollment_json_info)

                else:
                    root_logger.info(
                        'Invalid API Response (' + str(enrollment_details.status_code) + '): Unable to fetch Enrollment/Certificate details in production for enrollment-id: ' + str(enrollmentId))
                    root_logger.info(
                        'Reason: ' + json.dumps(enrollment_details.json(), indent=4))
                    print('\n')

            if args.xlsx:
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
                if output_file.endswith('csv'):
                    os.remove(output_file)
            elif args.json:
                root_logger.info('\nDone! Output file written here: ' + json_file)
                with open(os.path.join(json_file), 'w') as f:
                    f.write(json.dumps(final_json_array, indent=4))
                    #os.remove(output_file)
            else:
                #Default is csv format
                print('')
                root_logger.info('Done! Output file written here: ' + output_file)

        else:
            root_logger.info("Unable to find local cache. Please run 'setup' again")
            exit(0)


def create(args):
    """
    Method for handling create action. This method is responsible to create a new enrollment/certificate.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
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
                print('')
                root_logger.info('Multiple contracts exist, please specify' +
                                ' --contract-id to use for new enrollment')
                print('')
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
            print('')
            root_logger.info('You are about to create a new ' + certificateContent['ra'] + ' ' + certificateContent['validationType'] + '-' + certificateContent['certificateType'] + ' enrollment for Common Name (CN) = ' + certificateContent['csr']['cn'])
            print('')
            root_logger.info('Do you wish to continue (Y/N)?')
            decision = input()
        else:
            decision = 'y'

        if decision == 'Y' or decision == 'y':
            root_logger.info(
                'Uploading certificate information and creating enrollment..')
            base_url, session = init_config(args.edgerc, args.section)
            cps_object = cps(base_url,args.account_key)
            # Send a request to create enrollment using wrapper function
            create_enrollmentResponse = cps_object.create_enrollment(
                session, contractId, data=updateJsonContent)
            if create_enrollmentResponse.status_code != 200 and create_enrollmentResponse.status_code != 202:
                print('')
                root_logger.info('FAILED to create certificate: ')
                root_logger.info('Response Code is: ' +
                                 str(create_enrollmentResponse.status_code))
                root_logger.info(json.dumps(
                    create_enrollmentResponse.json(), indent=4))
            else:
                root_logger.info('Successfully created Enrollment...')
                print('')
                root_logger.info('Refreshing local cache...')
                setup(args, invoker='create')
                root_logger.info('Done...')
        else:
            root_logger.info('Exiting...')
            exit(0)
    except FileNotFoundError:
        print('')
        root_logger.info('Filename: ' + fileName +
                         ' is not found in templates folder. Exiting.')
        print('')
        exit(1)
    except KeyError as missingKey:
        # This is caught if --force is not used and file is validated
        print('')
        root_logger.info(str(missingKey) +
                         ' is not found in input file and is mandatory.')
        print('')
        root_logger.info(
            'Error: Input yaml file does not seem valid. Please check file format.')
        print('')

        exit(1)


def update(args):
    """
    Method for handling update action. This method is responsible to update a specific enrollment.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
    force = args.force
    fileName = args.file
    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    enrollmentResult = check_enrollment_id(args)
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
                print('')
                root_logger.info('You are about to update enrollment-id: ' + str(enrollmentId) + ' and CN: ' + cn)
                print('')
                root_logger.info('Do you wish to continue? (Y/N)')
                decision = input()
            elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
                root_logger.debug(json.dumps(
                    enrollment_details_json, indent=4))
                print('')
                root_logger.info('There already exists a pending change for enrollment id: ' + str(enrollmentId) + ' and CN: ' + cn)
                print('')
                root_logger.info('Would you like to override? This will cancel the existing change and apply the new update.')
                print('')
                root_logger.info('Press (Y/N) to continue')
                decision = input()

    # User passed --force so just go ahead by selecting Y
    else:
        # This is --force mode, so hardcode decision to y
        decision = 'y'

    if decision == 'y' or decision == 'Y':
        print('')
        root_logger.info('Trying to update enrollment...')
        print('')
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
                'Unable to update due to the below reason:')
            print('')
            root_logger.info(json.dumps(
                update_enrollmentResponse.json(), indent=4))
        root_logger.debug(update_enrollmentResponse.status_code)
        root_logger.debug(json.dumps(
            update_enrollmentResponse.json(), indent=4))
    else:
        root_logger.info('Exiting...')
        exit(0)


def cancel(args):
    """
    Method for handling cancel action. This method is responsible to cancel a specific enrollment.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    enrollmentResult = check_enrollment_id(args)
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
                                 cn + ' with enrollment-id: ' + str(enrollmentId) + '.')
                print('\n')
                root_logger.info('If the certificate has never been active, this will also remove the enrollment. If this a third-party and there is a pending CSR, it will also be cancelled.')
                print('\n')
                root_logger.info('Do you wish to continue? (Y/N)')
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
                    print('')
                    root_logger.info(
                        'Cancelling the request with change ID: ' + str(changeId))
                    cancel_change_response = cps_object.cancel_change(
                        session, enrollmentId, changeId)
                    if cancel_change_response.status_code == 200:
                        print('')
                        root_logger.info('Cancellation successful')
                        print('')
                    else:
                        root_logger.debug(
                            'Invalid API Response (' + str(cancel_change_response.status_code) + '): Cancellation unsuccessful')
                else:
                    print('')
                    root_logger.info(
                        'Unable to determine change status.')
                exit(-1)
            else:
                print('')
                root_logger.info('Exiting...')
                print('')
        else:
            print('')
            root_logger.info(
                'Unable to determine change status.')
            exit(-1)

    else:
        print('')
        root_logger.info(
            'Invalid API Response: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
        exit(-1)

def delete(args):
    """
    Method for handling delete action. This method is responsible to delete a specific enrollment.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)
    cn = args.cn
    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    enrollmentResult = check_enrollment_id(args)
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
        if 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) > 0:
            ## It's good idea to cancel active changes before deleting
            print('')
            root_logger.info(
                'There is an active change for this certificate. Please cancel the change before deleting this enrollment')
            exit(-1)

        elif 'pendingChanges' in enrollment_details_json and len(enrollment_details_json['pendingChanges']) == 0:
            ## no pending changes, so delete
            if not args.force:
                root_logger.info('You are about to delete the live certificate which may impact production traffic for cn: ' +
                                 cn + ' with enrollment-id: ' + str(enrollmentId) + '.')
                print('\n')
                root_logger.info('Do you wish to continue? (Y/N)')
                decision = input()
            else:
                decision = 'y'

            # check the decision flag
            if decision == 'y' or decision == 'Y':
                
                root_logger.info(
                    'Deleting enrollment ID: ' + str(enrollmentId) + ' with CN: ' + cn )
                delete_change_response = cps_object.delete_enrollment(
                    session, enrollmentId)
                if delete_change_response.status_code == 200 or delete_change_response.status_code == 202:
                    print('')
                    root_logger.info('Deletion successful')
                    print('')
                    exit(0)
                else:
                    root_logger.debug(
                        'Invalid API Response (' + str(delete_change_response.status_code) + '): Deletion unsuccessful')
                    exit(-1)
                
            else:
                print('')
                root_logger.info('Exiting...')
                print('')
        else:
            print('')
            root_logger.info(
                'Unable to determine change status to delete enrollment')
            exit(-1)

    else:
        print('')
        root_logger.info(
            'Invalid API Response: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
        exit(-1)


def retrieve_enrollment(args):
    """
    Method for handling retrieve-enrollment action. This method is responsible to retrieve details of an
    enrollment.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """
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

    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    enrollmentResult = check_enrollment_id(args)
    if enrollmentResult['found'] is True:
        enrollmentId = enrollmentResult['enrollmentId']
        cn = enrollmentResult['cn']
    else:
        root_logger.info(
            'Enrollment not found. Please double check common name (CN) or enrollment-id.')
        exit(0)


    cn = args.cn

    if args.cn:
        root_logger.info('Getting details for ' + cn +
                         ' with enrollment-id: ' + str(enrollmentId))
    elif args.enrollment_id:
        root_logger.info('Getting details for enrollment-id: ' + str(enrollmentId))

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
            'Invalid API Response: ' + str(enrollment_details.status_code) + '. Unable to fetch Certificate details.')
        exit(-1)


def retrieve_deployed(args):
    """
    Method for handling retrieve-deployed action. This method is responsible to retrieve details of an
    deployed certificate.

    Parameters
    -----------
    args : <string>
        Default args parameter (usually no argument specified)
    Returns
    -------
    None
    """

    if not args.cn and not args.enrollment_id:
        root_logger.info(
            'common Name (--cn) or enrollment-id (--enrollment-id) is mandatory')
        exit(-1)

    if not args.leaf and not args.chain and not args.info:
        root_logger.info('Please specify Either --leaf --chain or --info')
        exit(-1)

    base_url, session = init_config(args.edgerc, args.section)
    cps_object = cps(base_url,args.account_key)

    enrollmentResult = check_enrollment_id(args)
    if enrollmentResult['found'] is True:
        enrollmentId = enrollmentResult['enrollmentId']
        cn = enrollmentResult['cn']
    else:
        root_logger.info(
            'Enrollment not found. Please double check common name (CN) or enrollment-id.')
        exit(0)

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

            certificate_details = certificate(deployment_details.json()['certificate'])

            print('\n')
            print('Network      :   ' + network)
            print('Common Name  :   ' + str(certificate_details.subject))
            print('Not Before   :   ' + str(certificate_details.not_valid_before))
            print('Expires      :   ' + str(certificate_details.expiration))
            print('Issuer       :   ' + str(certificate_details.issuer))
            if hasattr(certificate_details, 'sanList'):
                print('SANs         :   ' + str(certificate_details.sanList) + '\n')
            else:
                print('SANs         :   \n')
        else:
            root_logger.info('Either --info OR --cert is mandatory')

    else:
        root_logger.info('Invalid API Response (' + str(deployment_details.status_code) + '): Unable to fetch deployment details for enrollment-id ' + str(enrollmentId))


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

