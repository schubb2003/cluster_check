#!/usr/bin/env python
# author:     Joe McManus joe.mcmanus@solidfire.com
# Updated:     Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have been tested in lab situations, all use cases cannot be accounted for.
# version:     1.6 4-Dec-2017
# use: Query clusters and nodes for nagios info, or just command line 
# coding: utf-8
# usage: python <script> (IP|HOSTNAME) PORT USERNAME PASSWORD")
import requests
import base64
import json
import sys
import io
import os.path
import math
import socket
import re
import textwrap
import time 
import ssl
import warnings
import ipaddress
import argparse
from solidfire.factory import ElementFactory

version="1.6 2018-Feb-2"

#This is a nagios thing, nagionic you might say. 
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4
exit_status=STATE_OK

checkUtilization=1 #Generate Alerts on the utilization of cluster space
checkSessions=1    #Generate Alerts on the number of iSCSI sessions
checkDiskUse=0     #Generate Alerts on disk access 

# Set vars for connectivity using argparse
parser = argparse.ArgumentParser()
parser.add_argument('-sm', type=str,
                    required=True,
                    metavar='mvip',
                    help='MVIP/node name or IP')
parser.add_argument('-su', type=str,
                    required=True,
                    metavar='username',
                    help='username to connect with')
parser.add_argument('-sp', type=str,
                    required=True,
                    metavar='password',
                    help='password for user')
args = parser.parse_args()

mvip_ip = args.sm
user_name = args.su
user_pass = args.sp
num_sessions = 0
ensemble_count = 0
num_vols = 0
num_nodes = 0

#Check for a valid IP
def ip_check(ip):
    try:
        ipaddress.ip_address(mvip_ip)
    except ValueError:
        check_name(ip)

#Resolve Hostnames
def check_name(hostname):
    try:
         socket.gethostbyname(hostname)
    except: 
        print_usage("Unable to resolve hostname " + hostname) 

#Check if new data has been written to disk
def read_write_check(fileName, new_use):
    if os.path.isfile(fileName):
        try:
            f=open(fileName, 'r+')
            previous_use=f.readline()
            f.seek(0)
            f.write(new_use)
            f.truncate()
            f.close()
        except: 
            print_usage("Unable to open & write to " + fileName + " check perms or set checkDiskUse=0")
        if new_use == "00": 
            disk_use="No"
            exit_status=STATE_CRITICAL
        elif previous_use == new_use:
            disk_use="No"
            exit_status=STATE_WARNING
        else:
            disk_use="Yes"
            exit_status=STATE_OK

    else: 
        f=open(fileName, 'w')
        f.write(new_use)
        disk_use="n/a"
        f.close()
        exit_status=STATE_UNKNOWN
    return disk_use, exit_status

#Compare ranges of numbers        
def range_check(critical, warning, value):
    if value > critical:
        exit_status=STATE_CRITICAL
    elif value > warning:
        exit_status=STATE_WARNING
    else:
        exit_status=STATE_OK
    return exit_status

#Add a asterik to values that are in error
def add_note(test_result, exit_status, value):
    if test_result != 0:
        value=value + "*"
        if test_result > exit_status:
            exit_status = test_result
    return exit_status, value

#Print a table
def pretty_print(description, value, width):
    #When printing values wider than the second column, split and print them
    int_width = (int(width/2))
    if len(value) > int_width:
        print("| "  + description.ljust(int_width) + " |" + "|".rjust(int_width + 1))
        i=0
        wrapped=textwrap.wrap(value, 18) 
        for loop in wrapped:
            print("| ".ljust(int_width+2) + " | " + loop + "|".rjust(int_width-(len(loop))))
            i=i+1
    else: 
        print( "| " + description.ljust(int_width) + " | " + value  + "|".rjust(int_width-(len(value))))

#Check to see if we were provided a name, and check that we can resolve it.

sfe = ElementFactory.create(mvip_ip, user_name, user_pass,print_ascii_art=False,timeout=300)
cluster_info = sfe.get_cluster_info()
cluster_name = cluster_info.cluster_info.name
mvip_ip = cluster_info.cluster_info.mvip
mvip_node = cluster_info.cluster_info.mvip_node_id
mvip_bond = cluster_info.cluster_info.mvip_interface
svip_ip = cluster_info.cluster_info.svip
svip_bond = cluster_info.cluster_info.svip_interface
svip_node = cluster_info.cluster_info.svip_node_id
encrypt_state = cluster_info.cluster_info.encryption_at_rest_state
ensemble_member = cluster_info.cluster_info.ensemble
iqn_id = cluster_info.cluster_info.unique_id
if cluster_info.cluster_info.rep_count == 2:
    helix_protection = 'double'
# Commented lines below are for understanding rep_count
# There is no triple or quadruple helix currently
# elif cluster_info.cluster_info.rep_count == 3:
    # helix_protection = 'triple'
# elif cluster_info.cluster_info.rep_count == 4:
    # helix_protection = "quadruple"
else:
    sys.exit("unknown helix type, script has exited")

cluster_version_info = sfe.get_cluster_version_info()
element_api_ver = cluster_version_info.cluster_apiversion
element_os_ver = cluster_version_info.cluster_version
drive_list = sfe.list_drives()

cluster_state = sfe.get_cluster_state(force=True)
for node in cluster_state.nodes:
    num_nodes += 1
    if node.node_id != 0:
        num_data_drives = 0
        num_meta_drives = 0
        error_data_drives = 0
        error_meta_drives = 0
        for drive in drive_list.drives:
            if drive.node_id == node.node_id and drive.type == "block" and drive.status == "active":
                num_data_drives +=1
            elif drive.node_id == node.node_id and drive.type == "volume" and drive.status == "active":
                num_meta_drives += 1
            elif drive.node_id == node.node_id and drive.type == "block" and drive.status != "active":
                error_data_drives += 1
            elif drive.node_id == node.node_id and drive.type == "volume" and drive.status != "active":
                error_meta_drives +=1
            else:
                continue                
        try:
            cluster_state = node.result.state
            cluster_name = node.result.cluster
            ensemble_count += 1
            if sys.stdout.isatty():
                print("+" + "-"*83 + "+")
                print("| SolidFire Monitoring Plugin v." + version + " Node information |".rjust(39))
                print("+" + "-"*83 + "+")
                pretty_print("Node Status", cluster_state, 80)
                pretty_print("Cluster Name", cluster_name, 80)
                pretty_print("Node ID", str(node.node_id), 80)
                pretty_print("Active data drives", str(num_data_drives), 80)
                pretty_print("Active metadata drives", str(num_meta_drives), 80)
                if error_data_drives > 0:
                    pretty_print("DATA DRIVES IN ERROR", str(error_data_drives)+" <<-- DRIVE IN ERROR", 80)
                if error_meta_drives > 0:
                    pretty_print("METADATA DRIVES IN ERROR", str(error_meta_drives)+" <<-- DRIVE IN ERROR", 80)
                pretty_print("MVIP", mvip_ip , 80)
                pretty_print("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
                print("+" + "-"*83 + "+")

            else:
                print ("Node Status: " + cluster_state + " Cluster Name: " + cluster_name + " MVIP: " + mvip_ip)

        except AttributeError:
            error_msg = "Node is not part of the cluster"
            error_na = "N/A"
            print("+" + "-"*83 + "+")
            print("| SolidFire Monitoring Plugin v." + version + " Node information |".rjust(39))
            print("+" + "-"*83 + "+")
            pretty_print("Node Status", error_msg, 80)
            pretty_print("Cluster Name", error_na, 80)
            pretty_print("Node ID", str(node.node_id), 80)
            pretty_print("Active data drives", str(num_data_drives), 80)
            pretty_print("Active metadata drives", str(num_meta_drives), 80)
            if error_data_drives > 0:
                pretty_print("DATA DRIVES IN ERROR", str(error_data_drives)+" <<-- DRIVE IN ERROR", 80)
            if error_meta_drives > 0:
                pretty_print("METADATA DRIVES IN ERROR", str(error_meta_drives)+" <<-- DRIVE IN ERROR", 80)
            pretty_print("MVIP", error_na, 80)
            pretty_print("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
            print("+" + "-"*83 + "+")      

iscsi_sessions = sfe.list_iscsisessions()
for session in iscsi_sessions.sessions:
    num_sessions +=1

cluster_stats = sfe.get_cluster_stats()
read_bytes = cluster_stats.cluster_stats.read_bytes
read_ops = cluster_stats.cluster_stats.read_ops
read_latent = cluster_stats.cluster_stats.read_latency_usec
write_bytes = cluster_stats.cluster_stats.write_bytes
write_ops = cluster_stats.cluster_stats.write_ops
write_latent = cluster_stats.cluster_stats.write_latency_usec
cluster_util = cluster_stats.cluster_stats.cluster_utilization
total_bytes = read_bytes + write_bytes
total_ops = read_ops + write_ops
average_iop_size = cluster_stats.cluster_stats.average_iopsize
pct_read_bytes = round((read_bytes/total_bytes)*100,2)
pct_write_bytes =  round((write_bytes/total_bytes)*100,2)
pct_read_ops =  round((read_ops/total_ops)*100,2)
pct_write_ops =  round((write_ops/total_ops)*100,2)
cluster_latent = cluster_stats.cluster_stats.latency_usec

vol_list = sfe.list_volumes()
for vol in vol_list.volumes:
	num_vols += 1 

if checkDiskUse == 1:
    fileName="/tmp/cluster-" + mvip_ip + ".txt"
    new_use=cluster_read_bytes + cluster_write_bytes
    disk_use, test_result=read_write_check(fileName, new_use)
    exit_status, disk_use=add_note(test_result, exit_status, disk_use)

else: 
    disk_use="n/a"

if checkUtilization == 1:
    test_result=range_check(90, 80, float(cluster_util))
    exit_status, cluster_util=add_note(test_result, exit_status, cluster_util)    

#In SolidFire OS v.5 we have a soft limit of 250 Volumes * 4 active sessions per node
maxSessions=ensemble_count * 1000
warnSessions=maxSessions * .90
if checkSessions == 1:
    test_result=range_check(maxSessions, warnSessions, num_sessions)
    exit_status, num_sessions=add_note(test_result, exit_status, str(num_sessions))    
ensemble_string = ('%s' % ' '.join(map(str, ensemble_member)))
ensemble_string = ensemble_string.strip()
 
#check to see if we are being called from a terminal
if sys.stdout.isatty():
    print("+" + "-"*83 + "+")
    print("| SolidFire Monitoring Plugin v." + version + " Cluster information |".rjust(39))
    print("+" + "-"*83 + "+")
    pretty_print("Cluster", mvip_ip , 80)
    pretty_print("Version", element_os_ver, 80)
    pretty_print("iSCSI Sessions", str(num_sessions) , 80)
    pretty_print("Node count", str(num_nodes) , 80)
    pretty_print("Volume Count", str(num_vols) , 80)
    pretty_print("Cluster Name", cluster_name , 80)
    #pretty_print("Ensemble Members", str('[%s]' % ', '.join(map(str, ensemble))) , 80)
    pretty_print("Ensemble Members", ensemble_string , 80)
    pretty_print("Helix protection", helix_protection, 80)
    pretty_print("Encryption", encrypt_state, 80)
    pretty_print("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
    if exit_status == 0:
        print_status="OK"
    elif exit_status == 1:
        print_status="*Warning"
    elif exit_status == 2:
        print_status="*Critical"
    elif exit_status == 3:
        print_status="*Unknown"
    pretty_print("Exit State ", print_status , 80)
    print("+" + "-"*83 + "+")
    
else:
    # Untested as all my terminals are TTY
    print("Cluster IPs: {} + \
		  Version: {} + \
		  Disk Activity: {} + \
          Read Bytes: {} + \
		  Write Bytes: {} + \
          Utilization: {} + \
          Node count: {} + \
		  ISCSI Sessions: {} + \
		  Volume count: {} + \
          Name: {} + \
          Ensemble {}".format(mvip_ip,
                              cluster_version,
                              disk_use,
                              cluster_read_bytes,
                              cluster_write_bytes,
                              cluster_util,
                              num_nodes,
                              num_sessions,
                              num_vols,
                              ensemble_string
                              )
         )

if sys.stdout.isatty():
    print("+" + "-"*83 + "+")
    print("| SolidFire Monitoring Plugin v." + version + " IO information |".rjust(39))
    print("+" + "-"*83 + "+")    
    pretty_print("Disk Activity", disk_use, 80)
    pretty_print("Read Bytes", str(read_bytes), 80)
    pretty_print("Total Bytes", str(total_bytes), 80)
    pretty_print("Write Bytes", str(write_bytes), 80)
    pretty_print("Percent Read Bytes", str(pct_read_bytes), 80)
    pretty_print("Percent Write Bytes", str(pct_write_bytes), 80)
    pretty_print("Read Ops", str(read_ops), 80)
    pretty_print("Write Ops", str(write_ops), 80)
    pretty_print("Total Ops", str(total_ops), 80)
    pretty_print("Percent Read Ops", str(pct_read_ops), 80)
    pretty_print("Percent Write Ops", str(pct_write_ops), 80)
    pretty_print("Read Latency", str(read_latent), 80)
    pretty_print("Write Latency", str(write_latent), 80)
    pretty_print("cluster Latency", str(cluster_latent), 80)
    pretty_print("Utilization %", str(cluster_util) , 80)
    pretty_print("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
    if exit_status == 0:
        print_status="OK"
    elif exit_status == 1:
        print_status="*Warning"
    elif exit_status == 2:
        print_status="*Critical"
    elif exit_status == 3:
        print_status="*Unknown"
    pretty_print("Exit State ", print_status , 80)
    print("+" + "-"*83 + "+")
    
sys.exit(exit_status)