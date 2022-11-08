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

class headers(object):
    def __init__(self):
        self.data = {
          "category" : {
            "change-management-info" : {
                "info" : {
                  "Accept" : "application/vnd.akamai.cps.change-management-info.v3+json"
                },
                "update" : {
                  "Accept" : "application/vnd.akamai.cps.change-id.v1+json",
                  "Content-Type" : "application/vnd.akamai.cps.acknowledgement-with-hash.v1+json"
                },
                "deloyment-info" : {
                  "Accept" : "application/vnd.akamai.cps.deployment.v1+json"
                }
            },
            "lets-encrypt-challenges" : {
                "info" : {
                  "Accept" : "application/vnd.akamai.cps.dv-challenges.v1+json"
                },
                "update" : {
                  "Accept" : "application/vnd.akamai.cps.change-id.v1+json",
                  "Content-Type" : "application/vnd.akamai.cps.acknowledgement.v1+json"
                }
            },
            "post-verification-warnings" : {
                "info" : {
                  "Accept" : "application/vnd.akamai.cps.warnings.v1+json"
                },
                "update" : {
                  "Accept" : "application/vnd.akamai.cps.change-id.v1+json",
                  "Content-Type" : "application/vnd.akamai.cps.acknowledgement.v1+json"
                }
            },
            "pre-verification-warnings" : {
                "info" : {
                  "Accept" : "application/vnd.akamai.cps.warnings.v1+json"
                },
                "update" : {
                  "Accept" : "application/vnd.akamai.cps.change-id.v1+json",
                  "Content-Type" : "application/vnd.akamai.cps.acknowledgement.v1+json"
                }
            },
            "third-party-csr" : {
                "info" : {
                  "Accept" : "application/vnd.akamai.cps.csr.v2+json"
                },
                "update" : {
                  "Accept" : "application/vnd.akamai.cps.change-id.v1+json",
                  "Content-Type" : "application/vnd.akamai.cps.certificate-and-trust-chain.v2+json"
                }
            }
          }
        }
