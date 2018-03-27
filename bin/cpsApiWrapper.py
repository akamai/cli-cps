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


class cps(object):
    def __init__(self, access_hostname):
        self.access_hostname = access_hostname

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
        contracts__url = 'https://' + self.access_hostname + '/papi/v1/contracts/'
        contracts_response = session.get(contracts__url)
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
        update_enrollment_response = session.put(
            update_enrollment_url, data=data, headers=headers)
        return update_enrollment_response

    def list_enrollments(self, session, contractId):
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
        list_enrollments_url = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments?contractId=' + contractId
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
        cancel_change_response = session.delete(
            cancel_change_url, headers=headers)
        return cancel_change_response

    def get_certificate(self, session, enrollmentId):
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
            str(enrollmentId) + '/deployments/production'
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
        dvChangeInfo_response = session.get(dvChangeInfo_url, headers=headers)
        return dvChangeInfo_response


    def get_tp_change_info(self, session, endpoint):
        """
        Function to get third party change details

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        tpChangeInfo_response : tpChangeInfo_response
            (tpChangeInfo_response) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.csr.v1+json"
        }
        tpChangeInfo_url = 'https://' + self.access_hostname + endpoint
        tpChangeInfo_response = session.get(tpChangeInfo_url, headers=headers)
        return tpChangeInfo_response

    def custom_post_call(self, session, headers, endpoint, data='optional'):
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

        custom_url = 'https://' + self.access_hostname + endpoint
        if data == 'optional':
            custom_response = session.post(custom_url, headers=headers)
        else:
            custom_response = session.post(custom_url, data=data, headers=headers)
        return custom_response
