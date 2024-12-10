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
