""" Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.
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

import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime

class cps(object):
    def __init__(self, access_hostname, account_switch_key):
        self.access_hostname = access_hostname
        if account_switch_key != '':
            self.account_switch_key = '&accountSwitchKey=' + account_switch_key
        else:
            self.account_switch_key = ''

    def get_contracts(self, session):
        """
        Function to fetch all contracts

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        contracts_response : contracts_response
            (contracts_response) Object with all details
        """
        contracts_url = 'https://' + self.access_hostname + '/contract-api/v1/contracts/identifiers?depth=TOP'
        #This is to ensure accountSwitchKey works for internal users
        if '?' in contracts_url:
            contracts_url = contracts_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            contracts_url = contracts_url + self.account_switch_key
        contracts_response = session.get(contracts_url)
        return contracts_response

    def create_enrollment(self, session, contractId, data):
        """
        Function to Create an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        create_enrollmentRespose : create_enrollmentRespose
            (create_enrollmentRespose) Object with all details
        """
        headers = {
            "Content-Type": "application/vnd.akamai.cps.enrollment.v4+json",
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        create_enrollment_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments?contractId=' + contractId
        if '?' in create_enrollment_url:
            create_enrollment_url = create_enrollment_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            create_enrollment_url = create_enrollment_url + self.account_switch_key

        create_enrollment_response = session.post(
            create_enrollment_url, data=data, headers=headers)
        return create_enrollment_response

    def update_enrollment(self, session, enrollmentId, data):
        """
        Function to Create an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        update_enrollmentRespose : update_enrollmentRespose
            (update_enrollmentRespose) Object with all details
        """
        headers = {
            "Content-Type": "application/vnd.akamai.cps.enrollment.v4+json",
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        update_enrollment_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId) + '?allow-cancel-pending-changes=true'

        if '?' in update_enrollment_url:
            update_enrollment_url = update_enrollment_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            update_enrollment_url = update_enrollment_url + self.account_switch_key

        update_enrollment_response = session.put(
            update_enrollment_url, data=data, headers=headers)
        return update_enrollment_response

    def list_enrollments(self, session, contractId='optional'):
        """
        Function to List Enrollments

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        list_enrollmentsRespose : list_enrollmentsRespose
            (list_enrollmentsRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollments.v4+json"
        }
        if contractId == 'optional':
            list_enrollments_url = 'https://' + self.access_hostname + \
                '/cps/v2/enrollments'
        else:
            list_enrollments_url = 'https://' + self.access_hostname + \
                '/cps/v2/enrollments?contractId=' + contractId

        if '?' in list_enrollments_url:
            list_enrollments_url = list_enrollments_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            list_enrollments_url = list_enrollments_url + self.account_switch_key

        list_enrollments_response = session.get(
            list_enrollments_url, headers=headers)
        return list_enrollments_response

    def get_enrollment(self, session, enrollmentId):
        """
        Function to Get an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        get_enrollmentRespose : get_enrollmentRespose
            (get_enrollmentRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollment.v4+json"
        }
        get_enrollment_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId)

        if '?' in get_enrollment_url:
            get_enrollment_url = get_enrollment_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            get_enrollment_url = get_enrollment_url + self.account_switch_key

        get_enrollment_response = session.get(get_enrollment_url, headers=headers)
        return get_enrollment_response

    def get_change_status(self, session, enrollmentId, changeId):
        """
        Function to Get details about changes made to an enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        get_change_statusRespose : get_change_statusRespose
            (get_change_statusRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.change.v1+json"
        }
        get_change_status_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + \
            str(enrollmentId) + '/changes/' + str(changeId)

        if '?' in get_change_status_url:
            get_change_status_url = get_change_status_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            get_change_status_url = get_change_status_url + self.account_switch_key

        get_change_status_response = session.get(get_change_status_url, headers=headers)
        return get_change_status_response

    def cancel_change(self, session, enrollmentId, changeId):
        """
        Function to cancel a change

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cancel_change_response : cancel_change_response
            (cancel_change_response) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.change-id.v1+json"
        }
        cancel_change_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId) + '/changes/' + str(changeId)

        if '?' in cancel_change_url:
            cancel_change_url = cancel_change_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            cancel_change_url = cancel_change_url + self.account_switch_key

        cancel_change_response = session.delete(
            cancel_change_url, headers=headers)
        return cancel_change_response

    def delete_enrollment(self, session, enrollmentId):
        """
        Function to delete this enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        delete_enrollment_response : delete_enrollment_response
            (delete_enrollment_response) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }

        #/cps/v2/enrollments/{enrollmentId}
        delete_enrollment_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId)

        if '?' in delete_enrollment_url:
            delete_enrollment_url = delete_enrollment_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            delete_enrollment_url = delete_enrollment_url + self.account_switch_key

        delete_enrollment_response = session.delete(
            delete_enrollment_url, headers=headers)
        return delete_enrollment_response

    def get_certificate(self, session, enrollmentId, network='production'):
        """
        Function to Get a Certificate

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        get_certificate_response : get_certificate_response
            (get_certificate_response) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.deployment.v3+json"
        }
        get_certificate_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + \
            str(enrollmentId) + '/deployments/' + network

        if '?' in get_certificate_url:
            get_certificate_url = get_certificate_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            get_certificate_url = get_certificate_url + self.account_switch_key

        get_certificate_response = session.get(get_certificate_url, headers=headers)
        return get_certificate_response

    def get_dv_change_info(self, session, endpoint):
        """
        Function to Get a Certificate

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        customCall_response : customCall_response
            (customCall_response) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.dv-challenges.v2+json"
        }
        dvChangeInfo_url = 'https://' + self.access_hostname + endpoint

        if '?' in dvChangeInfo_url:
            dvChangeInfo_url = dvChangeInfo_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            dvChangeInfo_url = dvChangeInfo_url + self.account_switch_key

        dvChangeInfo_response = session.get(dvChangeInfo_url, headers=headers)
        return dvChangeInfo_response


    def custom_post_call(self, session, headers, endpoint, data='optional'):
        """
        Function to make a post call to a custom endpoint

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        custom_response : custom_response
            (custom_response) Object with all details
        """

        custom_url = 'https://' + self.access_hostname + endpoint

        if '?' in custom_url:
            custom_url = custom_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            custom_url = custom_url + self.account_switch_key

        if data == 'optional':
            custom_response = session.post(custom_url, headers=headers)
        else:
            custom_response = session.post(custom_url, data=data, headers=headers)
        return custom_response

    def custom_get_call(self, session, headers, endpoint):
        """
        Function to make a get call with a custom endpoint

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        get_response : get_response
            (get_response) Object with all details
        """
        custom_url = 'https://' + self.access_hostname + endpoint

        if '?' in custom_url:
            custom_url = custom_url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            custom_url = custom_url + self.account_switch_key

        custom_response = session.get(custom_url, headers=headers)
        return custom_response

# Below class encapsulates the certificate members, this is done to
# decode a certificate into its members or fields
class certificate(object):
    def __init__(self, certificate):
        self.cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

        self.oids = x509.oid.ExtensionOID()
        try:
            self.ext = self.cert.extensions.get_extension_for_oid(self.oids.SUBJECT_ALTERNATIVE_NAME)
            self.sanList = []
            self.sanList = str(self.ext.value.get_values_for_type(x509.DNSName)).replace(',',
                      '').replace('[', '').replace(']', '')
        except Exception:
            #Not every certificate will have SAN
            pass

        self.expiration = str(self.cert.not_valid_after.date()) + ' ' + str(self.cert.not_valid_after.time()) + ' UTC'

        for attribute in self.cert.subject:
            self.subject = attribute.value

        self.not_valid_before = str(self.cert.not_valid_before.date()) + ' ' + str(self.cert.not_valid_before.time()) + ' UTC'

        for attribute in self.cert.issuer:
            self.issuer = attribute.value
