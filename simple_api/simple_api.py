#!/usr/bin/env python3

from __future__ import print_function
import sys
import json
from fnmatch import fnmatch
import copy
import requests
import os.path
import urllib
import jwt # pip install pyjwt

##### Default Authentication Credentials #####
SETTINGS_FILE_NAME = "api-settings.conf"
SETTINGS_FILE_VERSION = 1
##############################################

class simpleapi():
    def __init__(self, user_server_root, user_vmc_public_api, user_refresh_token, user_jwt_token=None):
        if user_jwt_token is not None:
            self.server_root = user_server_root
            self.base_url = user_server_root
            self.access_token = user_jwt_token
            self.vmc_public_api = user_vmc_public_api
            self.refresh_token = user_refresh_token
        else:
            vmc_settings = self.settings_read()
            if user_server_root is None:
                self.server_root = vmc_settings['server_root']
                self.base_url = vmc_settings['server_root']
            else:
                self.server_root = user_server_root
                self.base_url = user_server_root
            if user_jwt_token is None:
                self.access_token = vmc_settings['access_token']
            else:
                self.access_token = user_jwt_token
            if user_vmc_public_api is None:
                self.vmc_public_api = vmc_settings['vmc_public_api']
            else:
                self.vmc_public_api = user_vmc_public_api
            if user_refresh_token is None:
                self.refresh_token = vmc_settings['refresh_token']
            else:
                self.refresh_token = user_refresh_token

    def set_vmc_org(self, org_id, token):
        self.server_root = self.server_root + '/' + org_id
        self.access_token = token

    def settings_read(self):
        # Read/decode settings file
        settings_file_name_full = os.path.join(os.path.dirname(os.path.realpath(__file__)), SETTINGS_FILE_NAME)
        if os.path.isfile(settings_file_name_full):
            try:
                with open(settings_file_name_full, 'r') as f:
                    vmc_settings = json.load(f)
            except Exception as ex:
                self.exit_error(400, "Error in reading/parsing the api-settings file.  Please reset the settings "
                                     "using the api-settings-set.py utility.", ex)
            if vmc_settings['settings_version'] == SETTINGS_FILE_VERSION:
                return vmc_settings
            elif vmc_settings['settings_version'] < SETTINGS_FILE_VERSION:
                return self.settings_upgrade(vmc_settings)
            else:
                self.exit_error(500, "The settings file being used is newer than the utility understands.  Please"
                                     " recreate the settings file using the api-settings-set.py utility or "
                                     "update the nsx-api-toolset.")
        else:
            self.exit_error(400, "Cannot find the api-settings file.  Please create one using the "
                                 "api-settings-set.py utility.")

    def settings_write(self, jwt_token, server_root=None):
        # Write/encode settings file
        new_settings = {}
        new_settings['settings_version'] = SETTINGS_FILE_VERSION
        new_settings['access_token'] = jwt_token
        if server_root is None:
            new_settings['server_root'] = "https://vmc.vmware.com"
        else:
            new_settings['server_root'] = server_root
        settings_file_name_full = os.path.join(os.path.dirname(os.path.realpath(__file__)), SETTINGS_FILE_NAME)
        try:
            with open(settings_file_name_full, 'w') as f:
                json.dump(new_settings, f)
        except Exception as ex:
            self.exit_error(500, "Failed to create settings file.", ex)

    def settings_upgrade(self, vmc_settings):
        # Upgrade settings file
        self.settings_write(jwt_token=vmc_settings['access_token'],
                            server_root=vmc_settings['server_root'])
        return vmc_settings

#    def api_session(self):
        # create the main API session with provided tokens
#        if self.session:
#            return self.session
#        try:
#            session = api_requests.APISession(self.mac_key, self.access_token)
#            return session
#        except APISessionError as ex:
#            self.exit_error(400, "Error in api_session.", ex)

    def exit_error(self, error_code, error_message=None, system_message=None):
        print(error_code)
        if error_message is not None:
            print(error_message)
        if system_message is not None:
            print(system_message)
        sys.exit(1)

    def exit_success(self):
        sys.exit(0)

    def api_get(self, request_uri, request_data={}):
        '''
        perform a RESTful GET and return the resulting json
        '''
        response_list = []
        try:
            sess_response = requests.get(
                    request_uri,
                    headers={
                        'Accept': 'application/json',
                        'Authorization': 'Bearer ' + self.access_token},
                    data=json.dumps(request_data))
        except Exception as ex:
            self.exit_error(400, "Error in api_get.  Cannot connect.  Check your server root address!", ex)
        if sess_response.status_code == 200 or sess_response.status_code == 201 or sess_response.status_code == 202:
            content_type = sess_response.headers.get('Content-Type')
            if (content_type and
                    content_type.lower().startswith('application/json')):
                if isinstance(sess_response.json(), list):
                    response_list = sess_response.json()
                else:
                    response_list.append(sess_response.json())
            elif (content_type and
                    content_type.lower().startswith('text/plain')):
                    response_list = sess_response
            else:
                self.exit_error(sess_response.status_code, "Error in api_get - Content type")
        else:
            print("Response: ", sess_response.json())
            self.exit_error(sess_response.status_code, "Error in api_get - HTTPS Status Code received from request.  "
                                                       "Please reference the error code with standard HTTPS error "
                                                       "responses.")
        #if len(response_list) == 0:
        #    self.exit_error(404, "Error in api_get.")
        return response_list

    def api_post(self, request_uri, request_data={}, action='post'):
        '''
        perform a RESTful POST and process the resulting json
        '''
        response_list = []
        try:
            if action == "put":
                sess_response = requests.put(
                    request_uri,
                    headers={
                        'Accept': 'application/json',
                        'Referer': self.server_root,
                        'Authorization': 'Bearer ' + self.access_token},
                    data=json.dumps(request_data))
            elif action == "patch":
                sess_response = requests.patch(
                    request_uri,
                    headers={
                        'Accept': 'application/json',
                        'Referer': self.server_root,
                        'Authorization': 'Bearer ' + self.access_token},
                    data=json.dumps(request_data))
            else:
                sess_response = requests.post(
                    request_uri,
                    headers={
                        'Accept': 'application/json',
                        'Referer': self.server_root,
                        'Authorization': 'Bearer ' + self.access_token},
                    data=json.dumps(request_data))
        except Exception as ex:
            self.exit_error(400, "Error in api_post.  Cannot connect.  Check your server root address!", ex)
        if sess_response.status_code == 200 or sess_response.status_code == 201 or sess_response.status_code == 202 or sess_response.status_code == 204 or sess_response.status_code == 304:
            content_type = sess_response.headers.get('Content-Type')
            if (content_type and
                    content_type.lower().startswith('application/json')):
                if isinstance(sess_response.json(), list):
                    response_list = sess_response.json()
                else:
                    response_list.append(sess_response.json())
            else:
                if sess_response.status_code != 304 or sess_response.status_code != 204:
                    print(sess_response._content)
                    # self.exit_error(sess_response.status_code, "Error in api_post - Content type")
        else:
            print(sess_response._content)
            self.exit_error(sess_response.status_code, "Error in api_post - Status Code")
        print('Status code: ', sess_response.status_code)
        print('Response: ', sess_response)
        # if len(response_list) == 0 and sess_response.status_code != 304:
        #     self.exit_error(404, "Error in api_post.")
        return sess_response

    def api_delete(self, request_uri, request_data=None):
        '''
        perform a RESTful DELETE and return the resulting json
        '''
        response_list = []
        try:
            if request_data:
                sess_response = requests.delete(
                        request_uri,
                        headers={
                            'Accept': 'application/json',
                            'Authorization': 'Bearer ' + self.access_token},
                        data=json.dumps(request_data))
            else:
                sess_response = requests.delete(
                        request_uri,
                        headers={
                            'Accept': 'application/json',
                            'Authorization': 'Bearer ' + self.access_token})
        except Exception as ex:
            self.exit_error(400, "Error in api_delete.  Cannot connect.  Check your server root address!", ex)
        if sess_response.status_code == 200 or sess_response.status_code == 201 or sess_response.status_code == 202 or sess_response.status_code == 204:
            content_type = sess_response.headers.get('Content-Type')
            if (content_type and
                    content_type.lower().startswith('application/json')):
                if isinstance(sess_response.json(), list):
                    response_list = sess_response.json()
                else:
                    response_list.append(sess_response.json())
            else:
                print('Status Code: ', sess_response.status_code)
                print('Response: ', sess_response)
                # self.exit_error(400, "Error in api_delete.", sess_response.status_code)
        else:
            self.exit_error(400, "Error in api_delete.", sess_response.status_code)
        if len(response_list) == 0:
            self.exit_error(404, "Error in api_delete.")
        return response_list

    def getByDotNotation(self, obj, ref ):
        val = obj
        for key in ref.split( '.' ):
            try:
                val = val[key]
            except KeyError:
                val = None
                break
        return val

    def search_fields(self, search_obj_list, search_fields):
        '''
        search fields for values
        '''
        if search_fields is not None:
            filtered_search_obj_list = []
            for i in search_obj_list:
                full_object_match = True
                for j in self.split_search_fields(search_fields):
                    try:
                        if not fnmatch(str(self.getByDotNotation(i, j[0])).lower(), str(j[1]).lower()):
                            full_object_match = False
                            break
                    except KeyError:
                        full_object_match = False
                        break
                if full_object_match:
                    filtered_search_obj_list.append(i)
        else:
            filtered_search_obj_list = search_obj_list
        return filtered_search_obj_list

    def filter_fields(self, filter_obj_list, filter_field_list):
        return_obj = []
        if filter_field_list is not None:
            for i in filter_obj_list:
                obj_dict = {}
                for j in filter_field_list:
                    keys = j.split('.')
                    if len(keys) == 1:
                        try:
                            obj_dict[j] = i[keys[0]]
                        except KeyError:
                            obj_dict[j] = None
                    else:
                        branch = obj_dict
                        for key in keys[0:-1]:
                            branch = branch.setdefault(key, {})
                        branch[keys[-1]] = branch.get(keys[-1], self.getByDotNotation(i, j))
                return_obj.append(obj_dict)
        else:
            return_obj = filter_obj_list
        return return_obj

    def split_search_fields(self, fields_list):
        '''
        Split search fields into lists for use (parse)
        '''
        split_fields_list = []
        for i in fields_list:
            new_list_value = str(i).split(":")
            if len(new_list_value) != 2:
                self.exit_error(400, "Error in split_search_fields.  Invalid field:value list.  "
                                     "Please check your search list.")
            split_fields_list.append(new_list_value)
        return split_fields_list

    def get_access_token(self, refresh_token=None):
        '''
        Get VMC access token using the SS refresh token
        '''
        uri = self.vmc_public_api
        if not refresh_token:
            refresh_token = self.refresh_token
        data = "refresh_token=%s" % refresh_token
        resp = requests.post(
               uri,
               headers={'Content-Type': 'application/x-www-form-urlencoded'},
               params=data
               )
        if resp.status_code == 200:
            token = resp.json()['access_token']
            org_id = jwt.decode(token, verify=False)['context_name']
            self.set_vmc_org(org_id, token)
            return token
        else:
            self.exit_error(400, "Unable to obtain access_token using refresh token")

    # Org Operations
    def get_org(self):
        '''
        Get VMC Org Details
        '''
        return self.api_get(self.server_root)

    def get_org_providers(self):
        '''
        Get VMC Org Providers
        '''
        uri = self.server_root + '/providers'
        return self.api_get(uri)

    def get_orgs(self):
        '''
        Get all VMC Organizations
        '''
        return self.api_get(self.base_url)

    def get_org_subscriptions(self, _id=None):
        '''
        Get Org Subscriptions
        '''
        uri = self.server_root + '/subscriptions'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def get_org_offers(self, product_type, region='us-west-2'):
        '''
        Get all offers available
        '''
        uri = self.server_root + '/offer-instances?region=%s&product_type=%s' % (region, product_type)
        return self.api_get(urllib.quote(uri, safe=':/=&'))

    def get_org_tasks(self, _id=None):
        '''
        List all or a specific taskxs for an Org
        '''
        uri = self.server_root + '/tasks'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def set_org_task(self, _id, request_data):
        '''
        Modify an existing task
        '''
        uri = self.server_root + '/tasks/' + _id
        return self.api_post(uri, request_data)

    def set_org_subscription(self, request_data):
        '''
        Create subscription for an Org
        '''
        uri = self.server_root + '/subscriptions'
        return self.api_post(uri, request_data)

    def delete_org_subscription(self, _id):
        '''
        Cancel a subscription for the Org
        '''
        uri = self.server_root + '/subscriptions/' + _id
        return self.api_delete(uri)

    # SDDC Operations
    def get_sddc_info(self, sddc_id=None):
        '''
        Get all or specific SDDC
        '''
        uri = self.server_root + '/sddcs/'
        if sddc_id:
            uri = uri + '/' + sddc_id
        return self.api_get(uri)

    def set_sddc(self, request_data):
        '''
        Provision SDDC
        '''
        uri = self.server_root + '/sddcs'
        return self.api_post(uri, request_data)

    def delete_sddc(self, sddc_id):
        '''
        Delete SDDC
        '''
        uri = self.server_root + '/sddcs/' + sddc_id
        return self.api_delete(uri)

    def get_public_ips(self, sddc_id, _id=None):
        '''
        Get all or a specific public IP within the SDDC
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/publicips'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def set_public_ip(self, sddc_id, request_data):
        '''
        Allocate public IPs for a SDDC
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/publicips'
        return self.api_post(uri, request_data)

    def delete_public_ip(self, sddc_id, _id):
        '''
        Free one public IP for a SDDC
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/publicips/' + _id
        return self.api_delete(uri)

    def patch_public_ip(self, sddc_id, _id, action, request_data):
        '''
        Attach or detach a public IP to a workload VM
        '''
        uri = '%s/sddcs/%s/def/publicips/%s?action=%s' % (
            self.server_root, sddc_id, _id, action)
        self.api_post(urllib.quote(uri, safe=':/=&'), request_data, action='patch')

    def get_mgw_public_ip(self, sddc_id, _id=None):
        '''
        Get one or all public IP for the MGW
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/mgw/publicips'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def set_public_dns(self, sddc_id):
        '''
        Update the DNS records of management VMs to use public IP addresses
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/dns/public'
        return self.api_post(uri, action='put')

    def set_private_dns(self, sddc_id):
        '''
        Update the DNS records of management VMs to use private IP addresses
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/dns/private'
        return self.api_post(uri, action='put')

    def get_cluster(self, sddc_id, _id=None):
        '''
        Get on or all clusters
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/clusters'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def create_cluster(self, sddc_id, request_data):
        '''
        Create a cluster
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/clusters'
        return self.api_post(uri, request_data)

    def delete_cluster(self, sddc_id, _id):
        '''
        Delete a cluster
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/clusters/' + _id
        return self.api_delete(uri)

    def esx_host(self, sddc_id, request_data):
        '''
        Add or remove ESX host
        '''
        uri = "%s/sddcs/%s/esxs?action=%s" % (
            self.server_root, sddc_id, action)
        
        return self.api_post(urllib.quote(uri, safe=':/=&'), request_data)

    # NSX Edge Operations
    def get_edge_status(self, sddc_id, edge):
        '''
        Get NSX Edge status
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/status" % (
            self.server_root, sddc_id, edge)
        return self.api_get(uri)

    def get_firewall_stats(self, sddc_id, edge):
        '''
        Get NSX Edge Firewall Statistics
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/statistics/dashboard/firewall" % (
            self.server_root, sddc_id, edge)
        return self.api_get(uri)

    def get_firewall_rule_stats(self, sddc_id, edge, rule_id):
        '''
        Retrieve statistics for a specific firewall rule
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/statistics/%s" % (
            self.server_root, sddc_id, edge, rule_id)

    def get_nat_config(self, sddc_id, edge):
        '''
        Get NSX edge NAT config
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/nat/config" % (
            self.server_root, sddc_id, edge)
        return self.api_get(uri)

    def set_nat_config(self, sddc_id, edge, request_body):
        '''
        Create or update NAT config on NSX edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/nat/config" % (
            self.server_root, sddc_id, edge)
        return self.api_post(uri, request_data, action='put')

    def delete_nat_config(self, sddc_id, edge):
        '''
        Delete NAT config on NSX edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/nat/config" % (
            self.server_root, sddc_id, edge)
        return self.api_delete(uri)

    def set_nat_config_rule(self, sddc_id, edge_id, request_data, _id=None):
        '''
        Create or update a NAT rule
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/nat/config/rules" % (
            self.server_root, sddc_id, edge)
        if _id:
            uri = uri + '/' + _id
            return self.post(uri, request_data, action='put')
        else:
            return self.post(uri, request_data)

    def get_firewall_config(self, sddc_id, edge):
        '''
        Get the firewall configuration for the NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config" % (
            self.server_root, sddc_id, edge)
        return self.api_get(uri)

    def set_firewall_config(self, sddc_id, edge, request_body):
        '''
        Configure firewall for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config" % (
            self.server_root, sddc_id, edge)
        return self.api_post(uri, request_data, action='put')

    def delete_firewall_config(self, sddc_id, edge):
        '''
        Delete firewall configuration for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config" % (
            self.server_root, sddc_id, edge)
        return self.api_delete(uri)

    def get_firewall_config_rule(self, sddc_id, edge, _id=None):
        '''
        Get NSX edge firewall config rule
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config/rules" % (
            self.server_root, sddc_id, edge)
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def set_firewall_config_rule(self, sddc_id, edge, request_body, _id=None):
        '''
        Create or update NSX edge firewall config rule
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config/rules" % (
            self.server_root, sddc_id, edge)
        if _id:
            uri = uri + '/' + _id
            return self.api_post(uri, request_body, action='put')
        else:
            return self.api_post(uri, request_body)

    def delete_firewall_config_rule(self, sddc_id, edge, _id):
        '''
        Delete NSX edge firewall config rule
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/firewall/config/rules/%s" % (
            self.server_root, sddc_id, edge, _id)
        return self.delete(uri)

    def get_cgw_id(self, sddc_id):
        '''
        Get the ID associated with the CGW
        Assume that presently there is only one CGW
        '''
        uri = self.server_root + '/sddcs/' + sddc_id
        resp = self.api_get(uri)
        return resp[0]['resource_config']['cgws'][0]

    def get_mgw_id(self, sddc_id):
        '''
        Get the ID associated with the MGW
        '''
        uri = self.server_root + '/sddcs/' + sddc_id
        resp = self.api_get(uri)
        return resp[0]['resource_config']['mgw_id']

    def get_nsxmgr_ip(self, sddc_id):
        '''
        Get the private IP of the NSX manager
        '''
        uri = self.server_root + '/sddcs/' + sddc_id
        resp = self.api_get(uri)
        return resp[0]['resource_config']['nsx_mgr_management_ip']

    def get_edge(self, sddc_id, edge_type='serviceGateway'):
        '''
        Get all the service gateways associated with the SDDC
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges?edgeType=' + edge_type
        return self.api_get(uri)

    def get_l3vpn_config(self, sddc_id, edge_id):
        '''
        Get the L3VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + '/ipsec/config'
        return self.api_get(uri)

    def set_l3vpn_config(self, sddc_id, edge_id, request_data):
        '''
        Update/create L3VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + '/ipsec/config'
        return self.api_post(uri, request_data, action='put')

    def delete_l3vpn_config(self, sddc_id, edge_id):
        '''
        Delete the L3VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + '/ipsec/config'
        return self.api_delete(uri)

    def get_l3vpn_peer_config(self, sddc_id, edge_id, object_type, _id):
        '''
        Get the L3VPN Peer object config
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + \
              '/peerConfig?objectType=' + object_type + '&' + _id
        return self.api_get(uri)

    def get_ipsec_stats(self, sddc_id, edge_id, interval=60):
        '''
        Retrieve ipsec dashboard statistics for Edge Gateway
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + \
              '/statistics/dashboard/ipsec'
        return self.api_get(uri)

    def get_vpn_stats(self, sddc_id, edge_id):
        '''
        Retrieve IPSec VPN statistics for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/ipsec/statistics" % (
            self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    def get_l2vpn_config(self, sddc_id, edge_id):
        '''
        Get the L2VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/cgws/' + edge_id + '/l2vpn/config'
        return self.api_get(uri)

    def set_l2vpn_config(self, sddc_id, edge_id, request_data):
        '''
        Update/create L2VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/cgws/' + edge_id + '/l2vpn/config'
        return self.api_post(uri, request_data, action='put')

    def delete_l2vpn_config(self, sddc_id, edge_id):
        '''
        Delete L2VPN config associated with a specific edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/cgws/' + edge_id + '/l2vpn/config'
        return self.api_delete(uri)

    def get_l2vpn_stats(self, sddc_id, edge_id):
        '''
        Retrieve L2VPN statistics for NSX Edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + \
              '/l2vpn/config/statistics'
        return self.api_get(uri)

    def get_interface_stats(self, sddc_id, edge_id):
        '''
        Retrieve interface statistics for NSX Edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + \
              '/statistics/interfaces'
        return self.api_get(uri)

    def get_dashboard_stats(self, sddc_id, edge_id):
        '''
        Retrieve interface dashboard statistics for NSX Edge
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/edges/' + edge_id + \
              '/statistics/dashboard/interface'
        return self.api_get(uri)

    def get_dns_config(self, sddc_id, edge_id):
        '''
        Get DNS server configuration for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dns/config" % (
            self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    def set_dns_config(self, sddc_id, edge_id, request_body):
        '''
        Configure DNS servers for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dns/config" % (
            self.server_root, sddc_id, edge_id)
        return self.api_post(uri, request_data, action='put')

    def enable_dns_config(self, sddc_id, edge_id, enable=True):
        '''
        Enable or Disable DNS configuration for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dns/config?enable=%s" % (
            self.server_root, sddc_id, edge_id, enable)
        return self.api_post(uri)

    def delete_dns_config(self, sddc_id, edge_id):
        '''
        Delete DNS servers on NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dns/config" % (
            self.server_root, sddc_id, edge_id)
        return self.api_delete(uri)

    def get_dns_stats(self, sddc_id, edge_id):
        '''
        Retrieve DNS server statistics from NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dns/statistics" % (
            self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    def get_vnics(self, sddc_id, edge_id):
        '''
        Retrieve all interfaces for the NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/vnics" % (self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    def get_dhcp_leaseinfo(self, sddc_id, edge_id):
        '''
        Get DHCP lease information from NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/dhcp/leaseinfo" % (
            self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    def get_internal_stats(self, sddc_id, edge_id):
        '''
        Get internal interface statistics for NSX Edge
        '''
        uri = "%s/sddcs/%s/networks/4.0/edges/%s/statistics/interfaces/internal" % (
            self.server_root, sddc_id, edge_id)
        return self.api_get(uri)

    # Operations on SDDC Networks
    def get_logical_networks(self, sddc_id, _id=None):
        '''
        Get VMC Logical Networks
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/networks'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def set_logical_networks(self, sddc_id, request_data, _id=None):
        '''
        Create/Update VMC Logical Networks
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/networks'
        if _id:
            uri = uri + '/' + _id
            return self.api_post(uri, request_data, action='put')
        else:
            return self.api_post(uri, request_data)

    def delete_logical_network(self, sddc_id, _id):
        '''
        Delete the specified logical network
        '''
        uri = self.server_root + '/sddcs/' + sddc_id + '/networks/4.0/sddc/networks/' + _id
        return self.api_delete(uri)

    # Account linking operations
    def get_account_link(self):
        '''
        Get a link that can be used on a customer account to start the linking process
        '''
        uri = self.server_root + '/account-link'
        return self.api_get(uri)

    def get_compatible_subnets(self, region='us-west-2', linkedAccountId=None):
        '''
        Get customer compatible subnets for account linking via a task
        '''
        uri = self.server_root + '/account-link/compatible-subnets-async?region=' + region
        if linkedAccountId:
            uri = uri + '&linkedAccounbtId=' + linkedAccountId
        return self.api_get(uri)

    def get_connected_accounts(self):
        '''
        Get a link that can be used on a customer account to start the linking process
        '''
        uri = self.server_root + '/account-link/connected-accounts'
        return self.api_get(uri)

    def set_compatible_subnets(self, request_data):
        '''
        Sets which subnet to use to link accounts and finishes the linking process
        '''
        uri = self.server_root + '/account-link/compatible-subnets'
        return self.api_post(uri, request_data)

    def set_linked_subnet(self, request_data):
        '''
        Sets which subnet to use to link accounts and finishes the linking process
        '''
        uri = self.server_root + '/account-link/compatible-subnets-async'
        return self.api_post(uri, request_data)

    def delete_linked_account(self, linkedAccountPathId):
        '''
        Delete a particular linked account
        '''
        uri = self.server_root + '/account-link/connected-accounts/' + linkedAccountPathId
        return self.api_delete(uri, request_data)


class pvt_simpleapi():
    def __init__(self, nsxmgr, username, password):
        self.nsxmgr = nsxmgr
        self.username = username
        self.password = password

    def exit_error(self, error_code, error_message=None, system_message=None):
        print(error_code)
        if error_message is not None:
            print(error_message)
        if system_message is not None:
            print(system_message)
        sys.exit(1)

    def exit_success(self):
        sys.exit(0)

    def api_get(self, request_uri, resp_type='json', verify=False, request_data={}):
        '''
        perform a RESTful GET and return the resulting response body
        '''
        response_list = []
        if resp_type == 'json':
            headers = {'Accept': 'application/json'}
        else:
            headers = {}
        try:
            sess_response = requests.get(
                    request_uri,
                    headers=headers,
                    auth=(self.username, self.password),
                    verify=verify,
                    data=json.dumps(request_data))
        except Exception as ex:
            self.exit_error(400, "Error in api_get.  Cannot connect.  Check your NSX Manager address!", ex)
        if sess_response.status_code == 200 or sess_response.status_code == 201 or sess_response.status_code == 202 or sess_response.status_code == 204:
            content_type = sess_response.headers.get('Content-Type')
            if (content_type and
                content_type.lower().startswith('application/json')):
                if isinstance(sess_response.json(), list):
                    response_list = sess_response.json()
                else:
                    response_list.append(sess_response.json())
            else:
                response_list = sess_response
        else:
            print("Response: ", sess_response.json())
            self.exit_error(sess_response.status_code, "Error in api_get - HTTPS Status Code received from request.  "
                                                       "Please reference the error code with standard HTTPS error "
                                                       "responses.")
        return response_list

    def api_post(self, request_uri, request_data={}, action='post', resp_type='json'):
        '''
        perform a RESTful POST and process the resulting json
        '''
        response_list = []
        if resp_type == 'json':
            headers = {'Accept': 'application/json'}
        else:
            headers = {}
        try:
            if action == "put":
                sess_response = requests.put(
                    request_uri,
                    headers=headers,
                    verify=False,
                    auth=(self.username, self.password),
                    data=json.dumps(request_data))
            elif action == "patch":
                sess_response = requests.patch(
                    request_uri,
                    headers=headers,
                    verify=False,
                    auth=(self.username, self.password),
                    data=json.dumps(request_data))
            else:
                sess_response = requests.post(
                    request_uri,
                    headers=headers,
                    verify=False,
                    auth=(self.username, self.password),
                    data=json.dumps(request_data))
        except Exception as ex:
            self.exit_error(400, "Error in api_post.  Cannot connect.  Check your server root address!", ex)
        if sess_response.status_code == 200 or sess_response.status_code == 201 or sess_response.status_code == 202 or sess_response.status_code == 204 or sess_response.status_code == 304:
            content_type = sess_response.headers.get('Content-Type')
            if (content_type and
                    content_type.lower().startswith('application/json')):
                if isinstance(sess_response.json(), list):
                    response_list = sess_response.json()
                else:
                    response_list.append(sess_response.json())
            else:
                if sess_response.status_code != 304 or sess_response.status_code != 204:
                    print(sess_response._content)
                    # self.exit_error(sess_response.status_code, "Error in api_post - Content type")
        else:
            print(sess_response._content)
            self.exit_error(sess_response.status_code, "Error in api_post - Status Code")
        print('Status code: ', sess_response.status_code)
        print('Response: ', sess_response)
        # if len(response_list) == 0 and sess_response.status_code != 304:
        #     self.exit_error(404, "Error in api_post.")
        return sess_response

    def get_l3vpn(self, edge):
        '''
        Get the L3VPN config using private endpoint
        '''
        uri = 'https://' + self.nsxmgr + '/api/4.0/edges/' + edge + '/ipsec/config'
        print('HTTP GET: ', uri)
        return self.api_get(uri)

    def get_l2vpn(self, edge):
        '''
        Get the L2VPN config using private endpoint
        '''
        uri = 'https://' + self.nsxmgr + '/api/4.0/sddc/cgws/' + edge + '/l2vpn/config'
        return self.api_get(uri)

    def get_networks(self, _id=None):
        '''
        Get the logical networks using private endpoint
        '''
        uri = 'https://' + self.nsxmgr + '/api/4.0/sddc/networks'
        if _id:
            uri = uri + '/' + _id
        return self.api_get(uri)

    def get_dns_config(self, edge):
        '''
        Get DNS server configuration for NSX Edge
        '''
        uri = "https://%s/api/4.0/edges/%s/dns/config" % (
            self.nsxmgr, edge)
        print("HTTP GET ", uri)
        return self.api_get(uri)

    def set_dns_config(self, edge, request_body):
        '''
        Configure DNS servers for NSX Edge
        '''
        uri = "https://%s/api/4.0/edges/%s/dns/config" % (
            self.nsxmgr, edge)
        return self.api_post(uri, request_data, action='put')

    def enable_dns_config(self, edge, enable=True):
        '''
        Enable or Disable DNS configuration for NSX Edge
        '''
        uri = "https://%s/api/4.0/edges/%s/dns/config?enable=%s" % (
            self.nsxmgr, edge, enable)
        return self.api_post(uri)

    def get_nat_config(self, edge):
        '''
        Get NAT configuration for NSX Edge
        '''
        uri = "https://%s/api/4.0/edges/%s/nat/config" % (
            self.nsxmgr, edge)
        return self.api_get(uri)
    def delete_dns_config(self, edge):
        '''
        Delete DNS servers on NSX Edge
        '''
        uri = "https://%s/api/4.0/edges/%s/dns/config" % (
            self.nsxmgr, edge)
        return self.api_delete(uri)
