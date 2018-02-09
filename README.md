# Simple API Toolbox

A python framework to invoke VMC simple APIs using both the public endpoints (simpleapi) as well as the private endpoints (pvt_simpleapi).

Also included is a sample bash script showing how the APIs can be invoked using cURL.

Getting started
----------------------------------
```
## Using the public API endpoints:

>>> from simple_api.simple_api import simpleapi
>>> session = simpleapi('https://vmc.vmware.com/vmc/api/orgs', 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize', 'OAUTH_REFRESH_TOKEN')
>>> token = session.get_access_token() # Require to obtain API access token and identify associated Org
>>> cgw = session.get_cgw_id('SDDC_ID')
>>> mgw = session.get_mgw_id('SDDC_ID')
>>> status = session.get_edge_status('SDDC_ID', mgw)

## Using the private API endpoints

>>> from simple_api.simple_api import simpleapi
>>> session = pvt_simpleapi('10.32.171.5', 'cloudadmin@vmc.local', CLOUDADMIN_PASSWORD)
>>> l3vpns = session.get_l3vpn('edge-2')

## TODO: The private simple APIs are incomplete and do not include all available functionality.
