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

    def getContracts(self, session):
        """
        Function to fetch all contracts

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        contractsResponse : contractsResponse
            (contractsResponse) Object with all details
        """
        contractsUrl = 'https://' + self.access_hostname + '/papi/v1/contracts/'
        contractsResponse = session.get(contractsUrl)
        return contractsResponse

    def createEnrollment(self, session, contractId, data):
        """
        Function to Create an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        createEnrollmentRespose : createEnrollmentRespose
            (createEnrollmentRespose) Object with all details
        """
        headers = {
            "Content-Type": "application/vnd.akamai.cps.enrollment.v4+json",
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        createEnrollmentUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments?contractId=' + contractId + '&deploy-not-after=2020-01-01&deploy-not-before=2018-01-01'
        createEnrollmentResponse = session.post(
            createEnrollmentUrl, data=data, headers=headers)
        return createEnrollmentResponse

    def updateEnrollment(self, session, enrollmentId, data):
        """
        Function to Create an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        updateEnrollmentRespose : updateEnrollmentRespose
            (updateEnrollmentRespose) Object with all details
        """
        headers = {
            "Content-Type": "application/vnd.akamai.cps.enrollment.v4+json",
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        updateEnrollmentUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId) + '?allow-cancel-pending-changes=true'
        updateEnrollmentResponse = session.put(
            updateEnrollmentUrl, data=data, headers=headers)
        return updateEnrollmentResponse

    def listEnrollments(self, session, contractId):
        """
        Function to List Enrollments

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        listEnrollmentsRespose : listEnrollmentsRespose
            (listEnrollmentsRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollments.v4+json"
        }
        listEnrollmentsUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments?contractId=' + contractId
        listEnrollmentsResponse = session.get(
            listEnrollmentsUrl, headers=headers)
        return listEnrollmentsResponse

    def getEnrollment(self, session, enrollmentId):
        """
        Function to Get an Enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        getEnrollmentRespose : getEnrollmentRespose
            (getEnrollmentRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollment.v4+json"
        }
        getEnrollmentUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId)
        getEnrollmentResponse = session.get(getEnrollmentUrl, headers=headers)
        return getEnrollmentResponse

    def getChangeStatus(self, session, enrollmentId, changeId):
        """
        Function to Get details about changes made to an enrollment

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        getChangeStatusRespose : getChangeStatusRespose
            (getChangeStatusRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.change.v1+json"
        }
        getChangeStatusUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + \
            str(enrollmentId) + '/changes/' + str(changeId)
        getChangeStatusResponse = session.get(getChangeStatusUrl, headers=headers)
        return getChangeStatusResponse

    def cancelChange(self, session, enrollmentId, changeId):
        """
        Function to cancel a change

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cancelChangeResponse : cancelChangeResponse
            (cancelChangeResponse) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.change-id.v1+json"
        }
        cancelChangeUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + str(enrollmentId) + '/changes/' + str(changeId)
        cancelChangeResponse = session.delete(
            cancelChangeUrl, headers=headers)
        return cancelChangeResponse

    def getCertificate(self, session, enrollmentId):
        """
        Function to Get a Certificate

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        getCertificateRespose : getCertificateRespose
            (getCertificateRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.deployment.v3+json"
        }
        getCertificateUrl = 'https://' + self.access_hostname + \
            '/cps/v2/enrollments/' + \
            str(enrollmentId) + '/deployments/production'
        getCertificateResponse = session.get(getCertificateUrl, headers=headers)
        return getCertificateResponse


    def getDvChangeInfo(self, session, endpoint):
        """
        Function to Get a Certificate

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        customCallRespose : customCallRespose
            (customCallRespose) Object with all details
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.dv-challenges.v2+json"
        }
        dvChangeInfoUrl = 'https://' + self.access_hostname + endpoint
        dvChangeInfoResponse = session.get(dvChangeInfoUrl, headers=headers)
        return dvChangeInfoResponse


    def customPostCall(self, session, headers, endpoint):
        """
        Function to Get a Certificate

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        customCallRespose : customCallRespose
            (customCallRespose) Object with all details
        """

        customUrl = 'https://' + self.access_hostname + endpoint
        customResponse = session.post(customUrl, headers=headers)
        return customResponse
