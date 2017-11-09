# cli-cps
Provides a way to interact with your Certificate Provisioning System via Open APIs and without manually having to go into the Luna Portal. Provides various functionality such as viewing current certificates, current status, certificate details, and the ability to update certificates and audit them.

## Local Install
* Python 3+
* pip install edgegrid-python

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the Get Started pagegetting started guide on developer.akamai.comthe developer portal.  
* When working through this process you need to give grants for the Certificate Provisionig System API.  The section in your configuration file should be called 'cps'.

## Functionality (version 0.0.1)
The initial version of the cps provides the following functionality:
* One-time setup/download of local policy ids necessary to invoke APIs quickly
* List current Certificates
* List details of individual certificate

## akamai-cps
Main program that wraps this functionality in a command line utility:
* [Setup](#setup)
* [Get Details of Certificate](#getCertificateDetails)
* [Get Current Status of Certificate](#getCertificateStatus)
* [Generate an Audit Report](#audit)

### Setup
Does a one time download of CPS Enrollment IDs and stores them in /setup folder for faster local retrieval. This command can be run anytime and will refresh the /setup folder based on the current list of policies.

```bash
%  akamai cps setup
```

### list
List Enrollments currently enrolled in akamai CPS

```bash
%  akamai cps list
```

### show
Get specific details for a enrollment. Available information include the complete JSON data as of now.

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

### download
Download the enrollment detail into json or yml folder in json or yml format respectively.

```bash
%  akamai cps download --cn demo.devops.com --format yml
%  akamai cps download --cn demo.devops.com --format json
```

The flags of interest for download are:

```
--cn <common name>  Common name to be used to download the certificate/enrollment information from CPS.
--format <json/yml/yaml>        Data format to be used to save the downloaded certificate information.

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
