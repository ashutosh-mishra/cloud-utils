import argparse
from googleapiclient import discovery
import googleapiclient.errors as err
from ipaddr import IPNetwork
import json
import logging

from oauth2client.client import GoogleCredentials
import os
from pprint import pprint

import requests
import sys
import time

from google.oauth2 import service_account



class RestApi():
    def __init__(self, creds_file):
        creds = GoogleCredentials.from_stream(creds_file)
        self.creds = creds.create_scoped(['https://www.googleapis.com/auth/cloud-platform'])

    def get_access_token(self):
        access_token = self.creds.get_access_token()
        return access_token.access_token

    def get(self, access_token, url):
        headers = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        params = {}
        r = requests.get(url, params=params, headers=headers)
        r.raise_for_status()
        return r.json()


class GcpOps():
    def __init__(self, creds_file):

        creds = service_account.Credentials.from_service_account_file(
            creds_file)

        creds = creds.with_scopes(
            ['https://www.googleapis.com/auth/cloud-platform'])
        self.log = logging.getLogger()
        self.creds_file = creds_file
        self.v1 = discovery.build('compute', 'v1', credentials=creds)
        self.beta = discovery.build('compute', 'beta', credentials=creds)

    def get_operation_status(self, op, project, region='', zone=''):
        while True:
            if op['status'] == 'RUNNING':
                if 'global' in op['selfLink']:
                    op = self.v1.globalOperations().get(project=project,
                                operation=op['name']).execute()
                elif 'zone' in op['selfLink']:
                    op = self.v1.zoneOperations().get(project=project,

                                operation=op['name'], zone=zone).execute()
                elif 'region' in op['selfLink']:
                    op = self.v1.regionOperations().get(project=project,
                                operation=op['name'], region=region).execute()
                time.sleep(1)
            elif op['status'] == 'DONE':
                if op.get('error'):
                    self.log.error("%s error while checking operation status" %op['error'])
                    raise Exception(op['error'])
                elif op.get('warning'):
                    self.log.debug("%s warning while checking operation status" %op['warning'])
                break

    def delete_subnetwork(self, project, subnetwork, region):
        try:
            op = self.v1.subnetworks().delete(project=project,
                                              subnetwork=subnetwork,
                                              region=region).execute()
            self.get_operation_status(op, project, region=region)
        except err.Error as ex:
            self.log.error("Deletion of subnetwork failed with error %s" %ex)
            raise Exception(str(ex))
        except Exception as ex:
            raise ex
        return True

    def delete_vpc(self, project, network):
        try:
            print '\t\tDeleting vpc %s' % network
            op = self.v1.networks().delete(project=project,
                                           network=network).execute()
            self.get_operation_status(op, project)
        except err.Error as ex:
            self.log.error("Deletion of vpc failed with error %s" %ex)
            raise Exception(str(ex))
        except Exception as ex:
            raise ex
        print '\tDeleted vpc %s' % network


    def delete_route(self, project, name):
        try:
            op = self.v1.routes().delete(project=project, route=name).execute()
            self.get_operation_status(op, project)
        except err.Error as ex:
            self.log.error("Deletion of routes failed with error %s" %ex)
            raise Exception(str(ex))
        except Exception as ex:
            raise ex

    def list_fw_rules(self, project, network=None):
        try:
            fwfilter = None
            if network:
                fwfilter = "network eq .*%s.*" % network
            fw_list = self.v1.firewalls().list(project=project, filter=fwfilter).execute()
            return fw_list
        except Exception as ex:
            self.log.error("Unable to list out firewall rule %s" % ex)
            return {}

    def delete_fw_rule(self, project, name):
        try:
            fw_op = self.v1.firewalls().delete(project=project, firewall=name).execute()
            self.get_operation_status(fw_op, project)
        except err.Error as ex:
            self.log.error("Firewall rules deletion failed %s" % ex)
            raise Exception(str(ex))
        except Exception as ex:
            raise ex

    def get_network(self, project, name):
        try:
            net = self.v1.networks().get(network=name, project=project).execute()
            return net
        except err.Error as ex:
            print "Unable to get network %s" %ex
            return {}
        except Exception as ex:
            raise ex

    def get_subnet(self, project, name, region):
        try:
            subnet = self.v1.subnetworks().get(
                project=project, region=region, subnetwork=name).execute()
            return subnet
        except err.Error as ex:
            self.log.error("Unable to get subnet %s" %ex)
            raise Exception(str(ex))
        except Exception as ex:
            raise ex

    def list_subnets(self, project, net_name, network=None):
        ''' conflict peers check is a list of all peer routes,
        if list is provided, check current subnets for overlap'''
        subnet_list = []
        self.log.debug('Listing subnets in network %s:%s' % (project, net_name))
        rest = RestApi(self.creds_file)
        if not network:
            network = self.get_network(project, net_name)

        access_token = rest.get_access_token()
        for url in network.get('subnetworks', []):
            subnet = rest.get(access_token, url)
            subnet_list.append(subnet)
        return subnet_list, network

    def list_routes(self, project, network=None):
        try:
            route_filter = None
            if network:
                route_filter = "network eq .*%s.*" % network
            route_list = self.v1.routes().list(project=project, filter=route_filter).execute()
            return route_list
        except Exception as ex:
            self.log.error("Listing of routes failed with error %s" %ex)
            return {}

    def delete_fw(self, project, network):
        fw_list = self.list_fw_rules(project, network)
        fw_rules = fw_list.get('items', [])
        for rule in fw_rules:
            print '\t\t\tDeleting fw rule: ', rule['name']
            self.delete_fw_rule(project, rule['name'])

    def delete_routes(self, project, network):
        routes_list = self.list_routes(project, network=network)
        routes = routes_list.get('items', [])
        for route in routes:
            if 'Default route to the Internet.' in route['description']:
                print '\t\tDeleteing route: ', route['name']
                self.delete_route(project, route['name'])

    def delete_peering(self, project, network, peering_list):
        for peering_name in peering_list:
            networks_remove_peering_request_body = {
                "name": peering_name,
            }
            print '\t\tdelete_peering: ', peering_name
            op = self.v1.networks().removePeering(project=project, network=network,
                     body=networks_remove_peering_request_body).execute()
            self.get_operation_status(op, project)


def delete_nw_resources(project, ops, network_name):
    print '\t\tDeleting firewall rules'
    ops.delete_fw(project, network_name)
    ops.delete_routes(project, network_name)
    network = ops.get_network(project, network_name)
    peering_name_list = [peering['name'] for peering in network.get('peerings', [])]
    ops.delete_peering(project, network_name, peering_name_list)
    time.sleep(10)
    ops.delete_vpc(project, network_name)

def main(project, ops, nw_list):
    print 'nw_list : ', nw_list
    not_deleted = 0
    not_found = 0
    for nw in nw_list:
        print '\n\tDeleting resources for the network: ', nw
        subnet_list, network = ops.list_subnets(project, nw)
        if not network:
            print '\tNetwork doesnt exist: %s\n' % nw
            not_found+=1
            continue
        for subnet in subnet_list:
            region = subnet['region'].split('/regions/')[1]
            subnet_name = subnet['name']
            try:
                print '\t\tDeteling subnet: ', subnet_name
                status = True
                status = ops.delete_subnetwork(project, subnet_name, region)
            except Exception as e:
                status = False
                print '\t\tDeleeting subnet failed with error: ', e
                not_deleted+=1
                continue
            if status:
                delete_nw_resources(project, ops, nw)
        if not subnet_list:
            delete_nw_resources(project, ops, nw)
    total_nws = len(nw_list)
    deleted_nws_count = total_nws - (not_deleted + not_found)
    print 'Total Networks: %d\nDeleted: %d, Not Deleted: %d, Not Found: %s\n' % (total_nws, deleted_nws_count, not_deleted, not_found)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True, help='GCP Project')
    parser.add_argument('--creds-file', required=True, help='Service account creds file')
    parser.add_argument('--networks', nargs='*', required=True, help='List of names of networks, separated by space')
    
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_args()

    creds_file = args.creds_file
    project = args.project
    nw_list = args.networks

    ops = GcpOps(creds_file)

    main(project, ops, nw_list)


