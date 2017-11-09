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
%  akamai-cps setup
```

### list
List current Visitor Prioritization Cloudlet policy names  

```bash
%  akamai-cps list
```

### show
Get specific details for a policy name. Available information include configurations that reference that policy, current version numbers on Akamai staging and production, version history, and current rule settings.

```bash
%  akamai-cps -show --cn demo.devops.com
```

The flags of interest for create are:

```
-policyName <policyName>    Specified Visitor Prioritization Cloudlet policy name
-version <version>          Specific version number for that policy name (optional)
-fromVersion <fromVersion>  If -version is not specified, list policy version details starting from -fromVersion value (optional)
-verbose                    If -version is specified, add -verbose to get full rule details including url paths and match criteria (optional)

```

### Throttle
Make an actual change to percentage value for a specific rule name in the policy.

```bash
%  akamai-cloudlet-vp -throttle 50 -policyName samplePolicyName -rule 'ruleName' -network staging
%  akamai-cloudlet-vp -throttle -1 -policyName samplePolicyName -rule 'ruleName' -network staging
%  akamai-cloudlet-vp -throttle disabled -policyName samplePolicyName -rule 'ruleName' -network prod
```

The flags of interest for create are:

```
-throttle <value>          Acceptable values are -1 (= All to Waiting Room), 0 <= 100, or 'disabled' (to disable rule)
-policyName <policyName>   Specified Visitor Prioritization Cloudlet policy name
-ruleName <ruleName>       Name of rule in policy that should be changed. Use single quotes ('') in case rule name has spaces. If multiple rules exist for the same name, all of them will be updated.
-network <network>         Either staging, prod, or production ; will make change based on latest version on that network

```

### Activate
Activate a specified version for a policy to the appropriate network (staging or production)

```bash
%  akamai-cloudlet-vp -activate -policyName samplePolicyName -version 87 -network staging
%  akamai-cloudlet-vp -activate -policyName samplePolicyName -version 71 -network prod
```

The flags of interest for create are:

```
-policyName <policyName>  Specified Visitor Prioritization Cloudlet policy name
-version <version>        Specific version number for that policy name
-network <network>        Either staging, prod, or production ; will make change based on latest version on that network

```

### GenerateRulesJson
Download the raw policy rules for a specified version in json format for local editing if desired.

```bash
%  akamai-cloudlet-vp -generateRulesJson -policyName samplePolicyName -version 87
%  akamai-cloudlet-vp -generateRulesJson -policyName samplePolicyName -version 71 -outputfile savefilename.json
```

The flags of interest for create are:

```
-policyName <policyName>  Specified Visitor Prioritization Cloudlet policy name
-version <version>        Specific version number for that policy name
-outputfile <filename>    Filename to be saved as in /rules folder (optional)

```

### createVersion
Download the raw policy rules for a specified version in json format for local editing if desired.

```bash
%  akamai-cloudlet-vp -createVersion -policyName samplePolicyName
%  akamai-cloudlet-vp -createVersion -policyName samplePolicyName -file filename.json
```

The flags of interest for create are:

```
-policyName <policyName>  Specified Visitor Prioritization Cloudlet policy name
-file <file>	          Filename of raw .json file to be used as policy details. This file should be in the /rules folder (optional)

```
