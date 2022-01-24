#!/bin/python
import json
import boto3
import csv
from typing import Any, Protocol
import os
import pandas as pd
import glob
import os as os
import glob as gl
import sys
from xlsxwriter.workbook import Workbook
import pathlib


def convert_to_json(o: Any) -> Any:
    t = type(o)

    if t is dict:
        return {k: convert_to_json(v) for k, v in o.items()}

    elif t is list or t is set:
        return [convert_to_json(item) for item in o]

    elif t is int or t is float or t is str or t is bool or o is None:
        return o

    else:
        return str(o)
        
csv_file_sg = open ("/tmp/sg.csv", "w")
csv_content_sg  = "Region, Group_Name, Group_ID, From_Port, To_port, CIDR\n"

csv_file_nacl = open ("/tmp/nacl.csv", "w")
csv_content_nacl  = "Region, NACL_ID, VPC_ID, Rule_NO, CIDR, Egress, Rule_Action\n"

csv_file_fw = open ("/tmp/fw.csv", "w")
csv_content_fw  = "Region, RuleGroupName, Protocl, Source_IP, SourcePort, Destination_IP, DestinationPort, Direction\n"

ec2_client = boto3.client('ec2')
response = ec2_client.describe_regions()
regions_data = response ["Regions"]

for regions in regions_data:
    Name = regions["RegionName"]

    #### Secuirty Groups ####
    session = boto3.Session(region_name=Name)
    client = session.client('ec2')
    ec2 = boto3.resource('ec2')
    response1=client.describe_security_groups()
    sg_data = response1 ["SecurityGroups"]

    for sg in sg_data:
        for portDetails in sg['IpPermissions']:
            fromPort = portDetails.get( 'FromPort', '')
            toPort = portDetails.get ('ToPort', '')
            for ip in portDetails.get( 'IpRanges', [] ):
                cidr = ip.get ('CidrIp', '')
            
                csv_content_sg += "{},{},{},{},{},{}\n".format(Name, sg["GroupName"], sg["GroupId"], fromPort, toPort, cidr)


    #### NACLs ####
    session = boto3.Session(region_name=Name)
    client = session.client('ec2')
    ec2 = boto3.resource('ec2')
    response2=client.describe_network_acls()
    nacl_data = response2 ["NetworkAcls"]

    for nacl in nacl_data:
        vpc_id = nacl.get("VpcId")
        naclID = nacl.get("NetworkAclId")          
        for entry in nacl["Entries"]:
            rule_no = entry.get("RuleNumber")
            cidr_block = entry.get("CidrBlock")
            egress = entry.get("Egress")
            rule_action = entry.get("RuleAction")
            if not entry[ 'Egress' ]:
                print(entry)

            csv_content_nacl += "{},{},{},{},{},{},{}\n".format(Name, naclID, vpc_id, rule_no, cidr_block, egress, rule_action)


    #### Firewall Rule Groups ####

    session = boto3.Session(region_name=Name)
    client = session.client('network-firewall')
    ec2 = boto3.resource('ec2')
    response3 = client.list_rule_groups()
    fw_rule_list = response3 ['RuleGroups']
    for fw_rule in fw_rule_list:
        rule_group = fw_rule.get('Arn')

        session = boto3.Session(region_name=Name)
        client = session.client('network-firewall')
        ec2 = boto3.resource('ec2')
        response4 = client.describe_rule_group(RuleGroupArn = str(rule_group))
        fw_rule_desc = response4 ['RuleGroup']

        for stateRules in fw_rule_desc[ 'RulesSource' ][ 'StatefulRules' ]:
            SourcePort = stateRules['Header']['SourcePort'].replace("[","").replace("]","")
            direction = stateRules['Header']['Direction']
            destPort = stateRules['Header']['DestinationPort'].replace("[","").replace("]","")
            protocol = stateRules['Header']['Protocol']
            source_ip = stateRules['Header']['Source'].replace("[","").replace("]","").replace(",",";")
            destiP = stateRules['Header']['Destination'].replace("[","").replace("]","")
            csv_content_fw += "{},{},{},{},{},{},{},{}\n".format(Name, fw_rule['Name'], protocol, source_ip, SourcePort, destiP, destPort, direction)   
        

csv_file_sg.write (csv_content_sg)
csv_file_nacl.write (csv_content_nacl)
csv_file_fw.write (csv_content_fw)

#### Code ####

csv_file_sg.close()
csv_file_nacl.close()
csv_file_fw.close()

tmpPath = '/tmp/'
os.chdir(r"/tmp/")
writer = pd.ExcelWriter('securityreport.xlsx', engine='xlsxwriter')
for csvFile in os.listdir( tmpPath ):
    if csvFile.endswith( 'csv' ):
        fileName = pathlib.Path( csvFile )
        inCsv = pd.read_csv( os.path.join( tmpPath, csvFile ) )
        inCsv.to_excel( writer, sheet_name = fileName.stem, index = False )
    
writer.save()


###########
def lambda_handler(event,context):
    
    srcFile = '/tmp/securityreport.xlsx'
    bucketName = 'aws-securityreport'


#def uploadToS3( bucketName: str, srcFile: str ):
    taskStatus = False
    try:
        s3_client = boto3.client('s3')
        uploadResp = s3_client.upload_file( srcFile, bucketName, 'securityreport.xlsx' )
        print( "Upload Resp ", uploadResp )
    except Exception as errMsg:
        print( errMsg )
    else:
        taskStatus = True
        
    return taskStatus

#if __name__ == '__main__':
#    lambda_handler(None, None)    
