# cli-cps
Provides a way to interact with the Akamai Certificate Provisioning System (CPS) via Open APIs. Provides various functionality such as viewing certificate details, generating audits, checking/acknowledging change statuses, creating/modifying certificates, and working with third party certificates.

## Local Install
* Python 3+
* pip install edgegrid-python

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the getting started guide on developer.akamai.com.  
* When working through this process you need to give your API credential the "CPS" and "Contracts-API_Contracts" Grant.  The section in your configuration file should be called 'cps'. 
* You may also use the --section <name> to use the specific section credentials from your .edgerc file

```
[cps]
client_secret = [CLIENT_SECRET]
host = [HOST]
access_token = [ACCESS_TOKEN_HERE]
client_token = [CLIENT_TOKEN_HERE]
```


## Functionality
Here is a summary of the current functionality:
* List current enrollments
* Generate an audit
* Retrieve enrollment details in yaml or json format
* Retrieve actual certificate details for what is deployed on the platform
* Create an enrollment from a yaml or json file
* Update an enrollment from a yaml or json file
* Cancel pending enrollment changes
* View and verify current change status
* Acknowledge pre/post verification warnings
* Acknowledge change management
* Work with 3rd party certificates (download/upload signed csr)

## akamai-cps
Main program file that wraps this functionality in a command line utility:
* [setup](#setup)
* [list](#list)
* [retrieve-enrollment](#retrieve-enrollment)
* [retrieve-deployed](#retrieve-deployed)
* [status](#status)
* [audit](#audit)
* [create](#create)
* [update](#update)
* [cancel](#cancel)
* [proceed](#proceed)


### setup
Does a one time download of CPS enrollments and common names for faster local retrieval. This command can be run anytime and will refresh the /setup folder based on the current list of enrollments.

```bash
%  akamai cps setup
```

### list
List all current enrollments in Akamai CPS

```bash
%  akamai cps list
```

### retrieve-enrollment
Get specific details for an enrollment and outputs the details in raw json or yaml format. Please specify either --cn or --enrollment-id

```bash
%  akamai cps retrieve-enrollment --cn sample.customer.com
%  akamai cps retrieve-enrollment --enrollment-id 12345
%  akamai cps retrieve-enrollment --cn sample.customer.com --json
%  akamai cps retrieve-enrollment --cn sample.customer.com --yaml
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--json                       Output in json format (Optional: will be default if nothing specified)
--yaml                       Output in yaml format (Optional)

```

### retrieve-deployed
Get specific details for the actual certificate deployed on the Akamai platform, including leaf, chain, or summary information. Please specify either --cn or --enrollment-id and one of --leaf, --chain, or --info arguments.

```bash
%  akamai cps retrieve-deployed --cn sample.customer.com --info
%  akamai cps retrieve-deployed --enrollment-id 12345 --info --network staging
%  akamai cps retrieve-deployed --cn sample.customer.com --leaf --network production
%  akamai cps retrieve-deployed --cn sample.customer.com --chain --network staging
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--leaf                       Leaf certificate details
--chain                      Full chain certificate details
--info                       Summary information about deployed certificate
--network                    Either staging or production (optional: default is production)
```


### status
Get current change status for an enrollment.

```bash
%  akamai cps status --cn sample.customer.com
%  akamai cps status --enrollment-id 12345
%  akamai cps status --enrollment-id 12345 --validation-type http (use if certificate type is DV)
%  akamai cps status --cn sample.customer.com --validation-type dns (use is certificate type is DV)
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--validation-type            Specify either 'http' or 'dns' (for DV certificates)
```

**If certificate type is third-party and CSR is ready, you may use this command to output the csr directly to a file:
```bash
%  akamai cps status --cn sample-cn.example.com > file.csr
```

### audit
Generate an audit of all enrollments to a .xlsx, .csv, or .json file

```bash
%  akamai cps audit
%  akamai cps audit --json
%  akamai cps audit --csv
%  akamai cps audit --xslx
%  akamai cps audit --output-file sample.xlsx
```

Here are the flags of interest:

```
--csv                       csv format (optional: if not specificed, default is .csv)
--json                      json format (optional: if not specificed, default is .csv)
--xlsx                      xslx format (optional: if not specificed, default is .csv) 
--output-file <value>       Filename to be saved (optional: if not specifed, generated file will be put in audit folder). 
```


### create
Create a new certificate enrollment.

```bash
%  akamai cps create --file /templates/sample.yml
%  akamai cps create --file /templates/sample.json --force
```

The flags of interest are:

```
--file <value>                Input file in yaml or json format with the enrollment details.
--force                       If specified, will not prompt for confirmation (optional)
```

### update
Update a specified enrollment.  Depending on the type of change, this may or may not trigger a new certificate deployment.

```bash
%  akamai cps update --cn test.edgekey.net --file sample.yml
%  akamai cps update --cn test.edgekey.net --file sample.json --force
```

The flags of interest are (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--file <value>               Input file in yaml or json format with the enrollment details.
--force                      If specified, will not prompt for confirmation (optional)
```


### cancel
Cancel any current pending change for an enrollment.  This will only delete the enrollment too if the certificate has never been deployed on the platform.

```bash
%  akamai cps cancel --cn sample.customer.com
%  akamai cps cancel --enrollment-id 12345
```

The flags of interest for cancel are (please specify either --cn or --enrollment-id):

```
--cn <value>                  Common name (CN) of the enrollment
--enrollment-id <value>       Enrollment id 
```

### proceed
If there is a pending change that requires user input, proceed accordingly

```bash
%  akamai cps proceed --cn sample.customer.com
%  akamai cps proceed --enrollment-id 12345
%  akamai cps proceed --enrollment-id 12345 --cert-file signed.csr --trust-file ca.crt (use if third party certificate and ready to upload signed csr)
%  akamai cps proceed --cn sample.customer.com --cert-file signed.csr --trust-file ca.crt (use if third party certifcate and ready to upload signed csr)
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--cert-file                  Signed certificate (PEM) file (for uploading third party certificates)
--trust-file                 Trust-chain (PEM) file (for uploading third party certificates)
```
