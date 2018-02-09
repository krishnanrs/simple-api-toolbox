#!/bin/bash

################
# Simple NSX API access via HTTP REST calls
#
#   This script relies on several utilities freely available for Linux and Windows OSs:
#    1. curl, URL transfer tool (http://curl.haxx.se/)
#    2. jq, json processor (https://stedolan.github.io/jq/)
#    3. openssl, command-line SSL/TLS wrappers (https://www.openssl.org/)
################

SDDC_ID="xxx-xxx-xxx-xxx"
ORG_ID="yyy-yyy-yyy-yyy"
OAUTH_REFRESH_TOKEN="zzz-zzz-zzz-zzz"

# Get the Access Token for VMC public endpoint API access
apiURI="https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
#apiURI="https://console-stg.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"

if [ `which jq` ]; then
    access_token=$(curl --silent -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "refresh_token=$OAUTH_REFRESH_TOKEN" $apiURI | jq .access_token | cut -f2 -d '"')
else
# This is a hack as it assumes the correct positioning of the access token in the output JSON
    access_token=$(curl --silent -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "refresh_token=$OAUTH_REFRESH_TOKEN" $apiURI | cut -f4 -d'"')
fi

if [ "x${access_token}" == "x" ]; then
    echo "Unable to obtain VMC access token"
    echo "Please check your OAUTH Refresher Token"
    exit 3
fi

# compose the Authorization header
authHeader="Bearer $access_token"

# make a real request. get SDDC logical networks
VMC_WEB_ROOT="https://vmc.vmware.com/vmc/api/orgs/${ORG_ID}"
#VMC_WEB_ROOT="https://vmc.vmware.com/vmc/api/orgs/${ORG_ID}/sddcs/${SDDC_ID}"
#VMC_WEB_ROOT="https://dev.skyscraper.vmware.com/vmc/api/operator/sddcs/${SDDC_ID}"
NSX_MGR_ROOT="https://10.171.46.5"
#apiURI="/networks/4.0/sddc/networks"
apiURI="/publicips"
#apiURI="/networks/4.0/edges?edgeType=serviceGateway"
#apiURI="/networks/4.0/sddc/cgws/edge-2/l2vpn/config"
#apiURI="/api/4.0/sddc/cgws/edge-2/l2vpn/config"

wlState=$(curl -v -X GET -H "Authorization: $authHeader" -H "Accept: application/json" $VMC_WEB_ROOT )
#wlState=$(curl --silent -X GET -H "Authorization: $authHeader" -H "Accept: application/json" $VMC_WEB_ROOT$apiURI )
#wlState=$(curl -k -v -X GET -u "admin:poiu0987" -H "Accept: application/json" $NSX_MGR_ROOT$apiURI )
# wlState=$(curl -k -v -X GET -u "cloudadmin@vmc.local:abcd1234" -H "Accept: application/json" $NSX_MGR_ROOT$apiURI )
retCode=`echo $?`
printf "%s " $wlState
