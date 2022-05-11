# Carbon Black Logic Apps connector and playbook templates

<img src="./Data%20Connectors/CarbonBlack.PNG" alt="drawing" width="20%"/><br>

## Table of Contents

1. [Overview](#overview)
1. [Deploy Custom Connector + 3 Playbook templates](#deployall)
1. [Authentication](#importantnotes)
1. [Prerequisites](#prerequisites)
1. [Deployment](#deployment)
1. [Post Deployment Steps](#postdeployment)
1. [References](#references)
1. [Known issues and limitations](#limitations)

## Overview

The Carbon Black Cloud is a cloud-native endpoint protection platform (EPP) that provides what you need to secure your endpoints using a single, lightweight agent and an easy-to-use console.

<a name="deployall">

## Deploy Custom Connector + three Playbook templates

This package includes:

* [Logic Apps custom connector for Carbon Black](./CarbonBlackConnector)

  ![custom connector](.//Data%20Connectors/CarbonBlackListOfActions.png)

* Three playbook templates leverage CarbonBlack custom connector:

  * [Response from Teams](./Playbooks/CarbonBlack-TakeDeviceActionFromTeams) - allow SOC to take action on suspicious devices arrived in incidents (apply a pre-defined policy or quarantine) and change incident configuration directly from Teams channel. Post information about the incident as a comment to the incident.
  * [Quarantine device](./Playbooks/CarbonBlack-QuarantineDevice) - move the device arrived in the incident to quarantine (if not already quarantined). Post information about the incident as a comment to the incident.
  * [Enrichment](./Playbooks/CarbonBlack-DeviceEnrichment) - collect information about the devices and post them as incident comment.

You can choose to deploy the whole package (Connector and all three playbook templates), or each one seperately from each folder.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzure-Sentinel%2Fhv%2FSolutions%2FCarbonBlack%2Fazuredeploy.json) [![Deploy to Azure](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzure-Sentinel%2Fhv%2FSolutions%2FCarbonBlack%2Fazuredeploy.json)

## CarbonBlack connector documentation

<a name="authentication">

## Authentication

This connector supports API Key authentication. When creating the connection for the custom connector, you will be asked to provide the API key which you generated in Carbon Black platform. [API Key authentication](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#creating-an-api-key).

<a name="prerequisites">

### Carbon Black Prerequisites

1. [Determine your Carbon Black Cloud API service endpoint.](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#building-your-base-urls) (e.g. https://defense.conferdeploy.net)
2. Generate an API key ([learn how](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#creating-an-api-key)), and grant it  **/appservices/** Access level.

  * The `/investigate/` Access level is also relevant for playbooks built from scratch and use the process API

3. For Response from Teams playbook, a policy needs to be created, so SOC will be able to move a device to it from the Teams adaptive card.

<a name="deployment">

### Deployment instructions

1. Deploy the custom connector and playbooks by clicking on "Deploy to Azure" button. This will take you to deploying an ARM Template wizard.
2. Fill in the required parameters for deploying custom connector and playbooks

| Parameters | Description |
|----------------|--------------|
|**For Custom Connector**|
|**Custom Connector name**| Enter the custom connector name (e.g. CarbonBlackConnector)|
|**Service Endpoint** | Enter the CarbonBlack cloud endpoint (e.g. https://defense.conferdeploy.net)|
|**For Playbooks**|
|**CarbonBlack-TakeDeviceActionFromTeams Playbook Name**|  Enter the playbook name (e.g. CarbonBlack-TakeDeviceActionFromTeams)|
|**CarbonBlack-DeviceEnrichment Playbook Name** |Enter the playbook name (e.g. CarbonBlack-QuarantineDevice)|
|**CarbonBlack-QuarantineDevice Playbook Name** | Enter the playbook name (e.g. CarbonBlack-DeviceEnrichment)|
|**OrganizationId** | Enter the OrganizationId|
|**PolicyId** | Enter the pre-defined Carbon Black Policy Id to which the Microsoft Teams adaptive card will offer to move device|
|**Teams GroupId** | Enter the Microsoft Teams channel id to send the adaptive card|
|**Teams ChannelId** | Enter the Microsoft Teams Group id to send the adaptive card [How to determine the Microsoft Teams channel and group ids](https://docs.microsoft.com/powershell/module/teams/get-teamchannel?view=teams-ps)|

<br>
<a name="postdeployment">

### Post-Deployment instructions

#### a. Authorize connections

Once deployment is complete, you will need to authorize each connection.

1. Click the Microsoft Sentinel connection resource
2. Click edit API connection
3. Click Authorize
4. Sign in
5. Click Save
6. Repeat steps for other connections such as Teams connection and CarbonBlack connector API Connection (For authorizing the Carbon Black connector API connection, API Key needs to be provided. The API Key is the combination of API Key / API Id).

#### b. Configurations in Sentinel

1. In Microsoft Sentinel analytical rules should be configured to trigger an incident with risky user account. 
2. Configure the automation rules to trigger the playbooks.

<a name="limitations">

## Known Issues and Limitations

1. Quarantine is not support for Linux OS devices.