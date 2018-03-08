# cli-cps
Provides a way to interact with the Akamai Certificate Provisioning System (CPS) via Open APIs. Provides various functionality such as viewing certificate details, generating audits, checking change statuses, and creating/modifying certificates.

## Local Install
* Python 3+
* pip install edgegrid-python

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the Get Started pagegetting started guide on developer.akamai.comthe developer portal.  
* When working through this process you need to give grants for the Certificate Provisionig System API.  The section in your configuration file should be called 'cps'.

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
* Show enrollment details
* Create an enrollment from a yaml or json file
* Update an enrollment from a yaml or json file
* Download enrollment details to a yaml or json file
* Cancel pending enrollment changes
* View and verify current change status (DV certs only for now)

## akamai-cps
Main program file that wraps this functionality in a command line utility:
* [setup](#setup)
* [list](#list)
* [show](#show)
* [download](#download)
* [status](#status)
* [audit](#audit)
* [create](#create)
* [update](#update)
* [cancel](#cancel)


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

### show
Get specific details for an enrollment and outputs the details in raw json format. Please specify either --cn or --enrollment-id

```bash
%  akamai cps show --cn sample.customer.com
%  akamai cps show --enrollment-id 12345
```


### download
Download the enrollment detail in either json or yaml format.  

```bash
%  akamai cps download --cn demo.devops.com --format yml
%  akamai cps download --cn demo.devops.com --format json
%  akamai cps download --enrollment-id 12345 --format json
%  akamai cps download --enrollment-id 12345 --format json --output-file sample.yaml
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--format <json/yml/yaml>     Desired file format (either json or yaml)
--output-file                Filename to be saved (optional). If not specified, will be saved in the /json or /yaml folder by default

```

### status
Get current change status for an enrollment. At this time only workflow for DV SAN is supported.

```bash
%  akamai cps status --cn sample.customer.com
%  akamai cps status --enrollment-id 12345
%  akamai cps status --enrollment-id 12345 --validation-type http
%  akamai cps status --cn sample.customer.com --validation-type dns
```

Here are the flags of interest (please specify either --cn or --enrollment-id):

```
--cn <value>                 Common name (CN) of the enrollment
--enrollment-id <value>      Enrollment id 
--validation-type            Specify either 'http' or 'dns' for DV SAN

```

### audit
Get specific details for a enrollment. Outputs the details in raw json format.

```bash
%  akamai cps show --cn demo.devops.com
```


### create
Create a new certificate request.

```bash
%  akamai cps create --file ./templates/ov_san.yml
```

The flags of interest for create are:

```
--file <value>          Absolute or relative path of input file in YAML/YML format containing certificate details.

```

### update
Activate a specified version for a policy to the appropriate network (staging or production)

```bash
%  akamai cps update --cn test.edgekey.net --file ./yml/demo_devops_com.yml
%  akamai cps update --cn test.edgekey.net --file ./yml/demo_devops_com.yml --force
```

The flags of interest for update are:

```
--cn <common name>  Common name to be used to update the certificate/enrollment information in CPS.
--file <value>        Absolute or relative path of input file in YAML/YML format containing updated certificate details.
--force An optional argument which forces the update without displaying the changed information.
```


### cancel
Cancel the latest change requested to a Certificate.

```bash
%  akamai cps cancel --cn demo.devops.com
```

The flags of interest for cancel are:

```
--cn <common name>  Common name to be used to cancel the certificate/enrollment information from CPS.

```
