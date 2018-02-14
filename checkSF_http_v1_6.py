#!/usr/bin/env python
# author: 	Joe McManus joe.mcmanus@solidfire.com
# Updated: 	Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have been tested in lab situations, all use cases cannot be accounted for.
# 	Updated to run using requests instead of urllib and corrected authentication stream
#	Added section for disabling SSL cert check due to lab on demand API calls failing		
# version: 	1.6 4-Dec-2017
# ipaddress will need to be installed via pip on 2.7 and below
# use: Query clusters and nodes for nagios info, or just command line 
# coding: utf-8
# usage: python <script> (IP|HOSTNAME) PORT USERNAME PASSWORD (mvip|node)")
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

version="1.6 2018-Feb-2"

#This is a nagios thing, nagionic you might say. 
STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3
STATE_DEPENDENT=4
exitStatus=STATE_OK

checkUtilization=1 #Generate Alerts on the utilization of cluster space
checkSessions=1    #Generate Alerts on the number of iSCSI sessions
checkDiskUse=0     #Generate Alerts on disk access 

def printUsage(error):
	print("ERROR: " + error)
	print("USAGE: " + sys.argv[0] + " (IP|HOSTNAME) PORT USERNAME PASSWORD (mvip|node)")
	sys.exit(STATE_UNKNOWN)

#Check command line options that are passed
def commandLineOptions():
	if len(sys.argv) < 6:
		printUsage("Incorrect Number of Arguments.")
	ip=sys.argv[1]
	port=sys.argv[2]
	username=sys.argv[3]
	password=sys.argv[4]
	ipType=sys.argv[5]
	if ipType != "mvip" and ipType != "node":
		printUsage("Invalid type specified, use node or mvip")
	return ip, port, username, password, ipType

def sendPost(ip, port, murl, username, password, jsonData, ipType):
	#REST URL
	url=("https://" + ip + ":" + port + murl)
	#Build user auth
	auth = (username + ":" + password)
	encodeKey = base64.b64encode(auth.encode('utf-8'))
	authKey = bytes.decode(encodeKey)
	print("-------------------------------------")
	#Set REST parameters
	headers = {
		'content-type': "application/json",
		'authorization': "Basic " + authKey
		}
	try:
		payload = (jsonData)
		##For areas without proper certs, uncomment the line blow and comment out three lines down
		##this line - response = requests.request("POST", url, data=payload, headers=headers)
		response = requests.request("POST", url, data=payload, headers=headers, verify=False)
		##For production with proper certs uncomment the line below and comment out the line above
		#response = requests.request("POST", url, data=payload, headers=headers)
		jsonResponse=json.loads(response.text)
		print("Warning in try: " + response.text)
	except:
		printUsage("Unable to connect to host: " + ip) 
		print("Warning in except" + response.text)
	
	#Check to see if we got a valid jsonResponse
	if 'result' not in jsonResponse:
		printUsage("Invalid response received.")
		print("Response validity: " + 'result')
	else:
		return jsonResponse['result']

#Check for a valid IP
def ipCheck(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        checkName(ip)

#Resolve Hostnames
def checkName(hostname):
	try:
 		socket.gethostbyname(hostname)
	except: 
		printUsage("Unable to resolve hostname " + hostname) 

#Check if new data has been written to disk
def readwriteCheck(fileName, newUse):
	if os.path.isfile(fileName):
		try:
			f=open(fileName, 'r+')
			previousUse=f.readline()
			f.seek(0)
			f.write(newUse)
			f.truncate()
			f.close()
		except: 
			printUsage("Unable to open & write to " + fileName + " check perms or set checkDiskUse=0")
		if newUse == "00": 
			diskUse="No"
			exitStatus=STATE_CRITICAL
		elif previousUse == newUse:
			diskUse="No"
			exitStatus=STATE_WARNING
		else:
			diskUse="Yes"
			exitStatus=STATE_OK
		
	else: 
		f=open(fileName, 'w')
		f.write(newUse)
		diskUse="n/a"
		f.close()
		exitStatus=STATE_UNKNOWN
	return diskUse, exitStatus

#Compare ranges of numbers		
def rangeCheck(critical, warning, value):
	if value > critical:
		exitStatus=STATE_CRITICAL
	elif value > warning:
		exitStatus=STATE_WARNING
	else:
		exitStatus=STATE_OK
	return exitStatus

#Add a asterik to values that are in error
def addNote(testResult, exitStatus, value):
	if testResult != 0:
		value=value + "*"
		if testResult > exitStatus:
			exitStatus = testResult
	return exitStatus, value

#Print a table
def prettyPrint(description, value, width):
	#When printing values wider than the second column, split and print them
	intWidth = (int(width/2))
	if len(value) > intWidth:
		print("| "  + description.ljust(intWidth) + " |" + "|".rjust(intWidth + 1))
		i=0
		wrapped=textwrap.wrap(value, 18) 
		for loop in wrapped:
			print("| ".ljust(intWidth+2) + " | " + loop + "|".rjust(intWidth-(len(loop))))
			i=i+1
	else: 
		print( "| " + description.ljust(intWidth) + " | " + value  + "|".rjust(intWidth-(len(value))))

		
murl="/json-rpc/9.0"
#Check the command line options
commandOpts=commandLineOptions()

ip=commandOpts[0]
port=commandOpts[1]
username=commandOpts[2]
password=commandOpts[3]
ipType=commandOpts[4]

#Check to see if we were provided a name, and check that we can resolve it.

if ipType == 'node':
	jsonData=json.dumps({"method":"GetClusterState","params":{},"id":1})
	try:
		response=sendPost(ip, port, murl, username, password, jsonData, ipType)
		clusterState=response['state']
	except:
		printUsage("State not found, are you sure this is a node?")

	if clusterState != "Active": 
		exitStatus=STATE_UNKNOWN
		clusterMvip="n/a"
		clusterName="n/a"
	else: 
		clusterName=response['cluster']
		jsonData=json.dumps({"method":"TestConnectMvip","params":{},"id":1})
		response=sendPost(ip, port, murl, username, password, jsonData, ipType)
		details=response['details']
		if 'mvip' in details:
			clusterMvip=details['mvip'] 
			exitStatus=STATE_OK
		else: 
			clusterMvip="*n/a Not in Cluster"
			exitStatus=STATE_WARNING

	if sys.stdout.isatty():
		print("+" + "-"*83 + "+")
		print("| SolidFire Monitoring Plugin v." + version + "|".rjust(39))
		print("+" + "-"*83 + "+")
		prettyPrint("Node Status", clusterState , 80)
		prettyPrint("Cluster Name", clusterName , 80)
		prettyPrint("MVIP", clusterMvip , 80)
		prettyPrint("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
		if exitStatus == 0:
			printStatus="OK"
		elif exitStatus == 1:
			printStatus="*Warning"
		elif exitStatus == 2:
			printStatus="*Critical"
		elif exitStatus == 3:
			printStatus="*Unknown"
		prettyPrint("Exit State ", printStatus , 80)
		print("+" + "-"*83 + "+")
		
	else:
		print ("Node Status: " + clusterState + " Cluster Name: " + clusterName + " MVIP: " + clusterMvip)

elif ipType == 'mvip': 
	#Get bytes and utilization from GetClusterStats
	jsonData=json.dumps({"method":"GetClusterStats","params":{},"id":1})
	response=sendPost(ip, port, murl, username, password, jsonData, ipType)
	details=response['clusterStats']
	clusterReadBytes=str(details['readBytes'])
	clusterWriteBytes=str(details['writeBytes'])
	clusterUse=str(details['clusterUtilization'])
	

	#Get ISCSI sessions from ListISCSISessions
	jsonData=json.dumps({"method":"ListISCSISessions","params":{},"id":1})
	response=sendPost(ip, port, murl, username, password, jsonData, ipType)
	details=response['sessions']
	numSessions=len(details)

	#Get name and members from GetClusterInfo
	jsonData=json.dumps({"method":"GetClusterInfo","params":{},"id":1})
	response=sendPost(ip, port, murl, username, password, jsonData, ipType)
	details=response['clusterInfo']
	clusterName=details['name']
	ensemble=details['ensemble']
	ensembleCount=len(ensemble)

	#get version info
	jsonData=json.dumps({"method":"GetClusterVersionInfo","params":{},"id":1})
	response=sendPost(ip, port, murl, username, password, jsonData, ipType)
	clusterVersion=response['clusterVersion']

	if checkDiskUse == 1:
		fileName="/tmp/cluster-" + ip + ".txt"
		newUse=clusterReadBytes + clusterWriteBytes
		diskUse, testResult=readwriteCheck(fileName, newUse)
		exitStatus, diskUse=addNote(testResult, exitStatus, diskUse)
		
	else: 
		diskUse="n/a"

	if checkUtilization == 1:
		testResult=rangeCheck(90, 80, float(clusterUse))
		exitStatus, clusterUse=addNote(testResult, exitStatus, clusterUse)	
		
	#In SolidFire OS v.5 we have a soft limit of 250 Volumes * 4 active sessions per node
	maxSessions=ensembleCount * 1000
	warnSessions=maxSessions * .90
	if checkSessions == 1:
		testResult=rangeCheck(maxSessions, warnSessions, numSessions)
		exitStatus, numSessions=addNote(testResult, exitStatus, str(numSessions))	
	ensemble_string = ('%s' % ' '.join(map(str, ensemble)))
	ensemble_string = ensemble_string.strip()	
	#check to see if we are being called from a terminal
	if sys.stdout.isatty():
		print("+" + "-"*83 + "+")
		print("| SolidFire Monitoring Plugin v." + version + "|".rjust(39))
		print("+" + "-"*83 + "+")
		prettyPrint("Cluster", ip , 80)
		prettyPrint("Version", clusterVersion , 80)
		prettyPrint("Disk Activity", diskUse , 80)
		prettyPrint("Read Bytes", clusterReadBytes , 80)
		prettyPrint("Write Bytes", clusterWriteBytes , 80)
		prettyPrint("Utilization %", clusterUse , 80)
		prettyPrint("iSCSI Sessions", str(numSessions) , 80)
		prettyPrint("Cluster Name", clusterName , 80)
		#prettyPrint("Ensemble Members", str('[%s]' % ', '.join(map(str, ensemble))) , 80)
		prettyPrint("Ensemble Members", ensemble_string , 80)
		prettyPrint("Execution Time ", time.asctime(time.localtime(time.time())) , 80)
		if exitStatus == 0:
			printStatus="OK"
		elif exitStatus == 1:
			printStatus="*Warning"
		elif exitStatus == 2:
			printStatus="*Critical"
		elif exitStatus == 3:
			printStatus="*Unknown"
		prettyPrint("Exit State ", printStatus , 80)
		print("+" + "-"*83 + "+")
	else:
		print("Cluster IP: " + ip + " Version: " + clusterVersion + " Disk Activity: " + diskUse + 
			" Read Bytes: " + clusterReadBytes + " Write Bytes: " + clusterWriteBytes + 
			" Utilization: " + clusterUse + " ISCSI Sessions: " + str(numSessions) + 
			" Name: " + clusterName + " Ensemble: "  + '[%s]' % ', '.join(map(str, ensemble)) )
 
sys.exit(exitStatus)