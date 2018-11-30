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

class sps(object):
    def __init__(self, access_hostname, account_switch_key):
        self.access_hostname = access_hostname
        if account_switch_key != '':
            self.account_switch_key = '&accountSwitchKey=' + account_switch_key
        else:
            self.account_switch_key = ''

   
    def create_enrollment_hostname(self, session, contractId, groupId, enrollmentId, edgeHost):
        """
        Function to Create an Enrollment Hostname

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        spsResponse : spsResponse
            (spsResponse) Object with all details
        """

        #application/x-www-form-urlencoded
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        url = "https://{}/config-secure-provisioning-service/v1/secure-edge-hosts/?contractId={}&groupId={}".format(self.access_hostname,contractId,groupId)
        
        data = "cnameHostname={}&enrollmentId={}&ipVersion=ipv4&product=alta".format(edgeHost,enrollmentId)

        if '?' in url:
            url = url + self.account_switch_key
        else:
            #Replace & with ? if there is no query string in URL
            self.account_switch_key = self.account_switch_key.translate(self.account_switch_key.maketrans('&','?'))
            url = url + self.account_switch_key

        create_enrollment_response = session.post(url, data=data, headers=headers)

        return create_enrollment_response

    