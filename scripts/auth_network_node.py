#!/usr/bin/python2
import base64
import getpass
import httplib
import json
import optparse
import sys
import urlparse
import ConfigParser
import os
import socket
from json import load
from urllib2 import urlopen
from time import sleep

def do_request(action, host, relative_url, headers, body):
    conn = httplib.HTTPSConnection(host)
    body_json = json.JSONEncoder().encode(body)
    conn.request(action, relative_url, body_json, headers)
    response = conn.getresponse()
    return conn, response

def get_token_v3(host, username, password, tenant):
    headers = { "Content-Type": "application/json" }
    body = {
        "auth":{
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": "default"},
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": tenant,
                    "domain": { "id": "default" }
                }
            }
        }
    }
    conn, response = do_request("POST", host,
            "/keystone/v3/auth/tokens",
            headers, body)

    if response.status not in (200, 201):
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    token = response.getheader('X-Subject-Token')
    response_body = json.loads(response.read())
    catalog = response_body['token']['catalog']
    conn.close()
    return token, catalog

def get_service_url(service_name, catalog, region):
    for service in catalog:
        if service['name'] == service_name:
            for endpoint in service['endpoints']:
                if endpoint['region'] == region and endpoint['interface'] == "public":
                    return endpoint['url']

def put_request(url, token, url_path, body):
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Auth-Token": token}
    _, net_location, path, _, _ = urlparse.urlsplit(url)
    full_path = "{0}/{1}".format(path, url_path)
    #import pdb; pdb.set_trace()
    conn, response = do_request("PUT", net_location, full_path, headers, body)

    if response.status != 200:
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_body = json.loads(response.read())
    return response_body

def add_role(url, token, body, host_id, role):
    url_path = "hosts/{0}/roles/{1}".format(host_id, role)
    role_add = put_request(url, token, url_path, body)
    return role_add

def add_pf9_cindervolume_base(url, token, host_id):
    body = {}
    role_add = add_role(url, token, body, host_id, "pf9-cindervolume-base")
    return role_add

def add_pf9_neutron_base(url, token, host_id):
    body = {}
    role_add = add_role(url, token, body, host_id, "pf9-neutron-base")
    return role_add

def add_pf9_cindervolume_lvm(url, token, host_id, backend_name, priv_ip):
    body = {
        "volume_driver":"cinder.volume.drivers.lvm.LVMVolumeDriver",
        "volume_backend_name":"{0}".format(backend_name),
        "iscsi_ip_address":"{0}".format(priv_ip)
    }
    role_add = add_role(url, token, body, host_id, "pf9-cindervolume-lvm")
    return role_add

def add_pf9_glance_role(url, token, host_id, pub_ip, glance_mount):
    body = {
        "endpoint_address":"{0}".format(pub_ip),
        "filesystem_store_datadir":"{0}".format(glance_mount),
        "update_public_glance_endpoint":"true"
    }
    role_add = add_role(url, token, body, host_id, "pf9-glance-role")
    return role_add

def add_pf9_neutron_ovs_agent(url, token, host_id, enable_dhcp, bridge_mappings, enable_tunneling, tunnel_types, priv_ip, net_type, enable_dvr):
    body = {
        "allow_dhcp_vms":"{0}".format(enable_dhcp),
        "bridge_mappings":"{0}".format(bridge_mappings),
        "enable_tunneling":"{0}".format(enable_tunneling),
        "tunnel_types":"{0}".format(tunnel_types),
        "local_ip":"{0}".format(priv_ip),
        "net_type":"{0}".format(net_type),
        "enable_distributed_routing":"{0}".format(enable_dvr)
    }
    role_add = add_role(url, token, body, host_id, "pf9-neutron-ovs-agent")
    return role_add

def add_pf9_neutron_l3_agent(url, token, host_id, agent_mode):
    body = {
        "agent_mode":"{0}".format(agent_mode)
    }
    role_add = add_role(url, token, body, host_id, "pf9-neutron-l3-agent")
    return role_add

def add_pf9_neutron_dhcp_agent(url, token, host_id, dns_servers, dns_domain):
    body = {
        "dnsmasq_dns_servers":"{0}".format(dns_servers),
        "dns_domain":"{0}".format(dns_domain)
    }

    role_add = add_role(url, token, body, host_id, "pf9-neutron-dhcp-agent")
    return role_add

def add_pf9_neutron_metadata_agent(url, token, host_id):
    body = {
    }
    role_add = add_role(url, token, body, host_id, "pf9-neutron-metadata-agent")
    return role_add

def add_pf9_ceilometer(url, token, host_id, kvm_instance_disk_path):
    body = {
        "kvm_instance_disk_path":"{0}".format(kvm_instance_disk_path)
    }
    role_add = add_role(url, token, body, host_id, "pf9-ceilometer")
    return role_add

def get_request(url, token, url_path):
    headers = {"Accept": "application/json", "X-Auth-Token": token}
    body = ""
    _, net_location, path, _, _ = urlparse.urlsplit(url)
    full_path = "{0}/{1}".format(path, url_path)
    # import pdb; pdb.set_trace()
    conn, response = do_request("GET", net_location, full_path, headers, body)

    if response.status != 200:
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_body = json.loads(response.read())
    return response_body

def get_node_pool(url, token, url_path):
    response_body = get_request(url, token, url_path)
    for node_pool in response_body:
        if node_pool['name'] == 'defaultPool':
            return node_pool['uuid']

def get_neutron_config(url, token):
    response_body = get_request(url, token, "services/neutron-server")
    if response_body['neutron']['DEFAULT']['router_distributed'] == 'false':
        enable_dvr='False'
    else:
        enable_dvr='True'
    if 'vxlan' in response_body['ml2']['ml2']['tenant_network_types']:
        enable_tunneling='True'
        tunnel_types='vxlan'
    elif 'gre' in response_body['ml2']['ml2']['tenant_network_types']:
        enable_tunneling='True'
        tunnel_types='gre'
    else:
        enable_tunneling='False'
    net_type = response_body['ml2']['ml2']['type_drivers'].replace('flat,','')
    dns_domain = response_body['neutron']['DEFAULT']['dns_domain']
    dns_servers = response_body['extra']['dnsmasq_dns_servers']
    return enable_tunneling, tunnel_types, net_type, enable_dvr, dns_domain, dns_servers 

def get_hosts(url, token, url_path):
    response_body = get_request(url, token, url_path)
    return response_body

def batch_auth_ceilometer(hosts_json, url, token):
    x = len(hosts_json)
    y = 0
    while y <= x:
        try:
            add_pf9_ceilometer(url, token, hosts_json[y]['id'], "/opt/pf9/data/instances/")
        except Exception as e:
            print e
        if y % 15 == 0 and y != 0:
            sleep(60)
        y+=1

def get_roles(url, token, url_path):
    response_body = get_request(url, token, url_path)
    print json.dumps(response_body)
    for role in response_body:
        print role['name']

def create_cluster(qbert_url, token, name, containersCidr, servicesCidr, externalDnsName, nodePoolUuid):
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Auth-Token": token}
    body = {
        "name": name,
        "containersCidr": containersCidr,
        "servicesCidr": servicesCidr,
        "externalDnsName": externalDnsName,
        "privileged": "true",
        "runtimeConfig": "",
        "nodePoolUuid": nodePoolUuid
    }
    _, net_location, path, _, _ = urlparse.urlsplit(qbert_url)
    node_pool_path = "{0}/{1}".format(path, "clusters")
    # import pdb; pdb.set_trace()
    conn, response = do_request("POST", net_location, node_pool_path, headers, body)

    if response.status != 200:
        print("{0}: {1}".format(response.status, response.reason))
        exit(1)

    response_body = json.loads(response.read())
    return response_body['uuid']

def get_private_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def get_host_id():
    host_ini = ConfigParser.ConfigParser()
    host_ini.read('/etc/pf9/host_id.conf')
    return host_ini.get('hostagent', 'host_id')

def get_public_ip():
    pub_ip = load(urlopen('https://api.ipify.org/?format=json'))['ip']
    return pub_ip

def validate_password(options):
    if not options.pw:
        options.pw = getpass.getpass()

def main():
    parser = optparse.OptionParser(usage="%prog --account_endpoint <endpoint> "
            "--region <region> --user <user> [--password <password>] [--tenant "
            "<tenant>]")
    parser.add_option('--account_endpoint', dest="endpoint", action="store",
            help="Account endpoint for the customer. Example: acme.platform9.net")
    parser.add_option('--region', dest="region", action="store",
            help="Region from where the installer needs to be downloaded")
    parser.add_option('--user', dest="user", action="store",
            help="Platform9 user account to use to retrieve the installer")
    parser.add_option('--password', dest="pw", action="store", default=None,
            help="User account password. Will be prompted, if not provided "
            "during script invocation")
    parser.add_option('--tenant', dest="tenant", action="store",
            default="service", help="Tenant to use for the user account. "
            "Defaults to 'service' tenant")

    options, remainder = parser.parse_args()
    if not (options.endpoint and options.region and 
            options.user and options.tenant):
        print "ERROR: Missing arguments"
        parser.print_usage()
        sys.exit(1)

    validate_password(options)

    token, catalog = get_token_v3(options.endpoint, options.user, options.pw, options.tenant)
    resmgr_url = "{0}/v1".format(get_service_url("resmgr", catalog, options.region))
    host_id = get_host_id()
    priv_ip = get_private_ip()
    pub_ip = get_public_ip()
    enable_tunneling, tunnel_types, net_type, enable_dvr, dns_domain, dns_servers = get_neutron_config(resmgr_url, token)
    add_pf9_cindervolume_base(resmgr_url, token, host_id)
    add_pf9_neutron_base(resmgr_url, token, host_id)
    add_pf9_glance_role(resmgr_url, token, host_id, pub_ip, "/var/opt/pf9/imagelibrary/data")
    add_pf9_cindervolume_lvm(resmgr_url, token, host_id, "LVM", priv_ip)
    add_pf9_neutron_ovs_agent(resmgr_url, token, host_id, "True", "external:br-ext", enable_tunneling, tunnel_types, priv_ip, net_type, enable_dvr)
    add_pf9_neutron_l3_agent(resmgr_url, token, host_id, "legacy")
    add_pf9_neutron_dhcp_agent(resmgr_url, token, host_id, dns_servers, dns_domain)
    add_pf9_neutron_metadata_agent(resmgr_url, token, host_id)


if __name__ == "__main__":
    main()

