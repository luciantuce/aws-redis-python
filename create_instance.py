#!/usr/local/bin/python
import boto, os.path, time, base64, subprocess, sys, argparse
from boto.vpc import VPCConnection
from boto.ec2 import EC2Connection


parser = argparse.ArgumentParser(
    description='This script creates Redis clusters in AWS')
parser.add_argument('-r', '--region', help='The region where the instances will be created. E.g. eu-central-1', required=True)
parser.add_argument('-n', '--numberofreadisserrvers', help='Number of Redis servers that will be started', required=True)
parser.add_argument('-k', '--key', help='The name of the key that will be used/created', required=True)
parser.add_argument('-v', '--vpc', help='The name of vpc in which the instances will be created; otherwise the default one will be used')
parser.add_argument('-s', '--subnet', help='The name of subnet(in the vpc mentioned with -v param) in which the instances will be created; otherwise the default one will be used')
parser.add_argument('-c', '--cidr', help='It will create a VPC with mask 24 and subnet 25')

args = parser.parse_args()



def create_vpc_and_subnet(conn_vpc,cidr):
    vpc_new = conn_vpc.create_vpc(cidr+"/24")
    conn_vpc.modify_vpc_attribute(vpc_new.id, enable_dns_hostnames=True)
    conn_vpc.modify_vpc_attribute(vpc_new.id, enable_dns_support=True)
    ig = conn_vpc.create_internet_gateway()
    conn.attach_internet_gateway(ig.id, vpc_new.id)
    rt = conn_vpc.create_route_table(vpc_new.id)
    conn_vpc.create_route(rt.id, '0.0.0.0/0', ig.id)
    subnet = conn_vpc.create_subnet(vpc_new.id, cidr+"/25")
    conn.associate_route_table(rt.id, subnet.id)
    return vpc_new

def create_sg(vpc):
    sg = ec2conn.create_security_group("Redis", "Redis Security Group", vpc.id)
    sg.authorize('tcp', 22, 22, '0.0.0.0/0')
    sg.authorize('tcp', 6379, 6379, '0.0.0.0/0')
    return sg

def create_key(key_name):
    key = conn.get_key_pair(key_name)
    conn.create_key_pair(key_name).save("~/.ssh")
    return key


def create_instances(keyname, sgid, subnetid, noofservers):
    code_to_install_redis = """#!/usr/bin/env bash
    sudo yum --enablerepo=epel install redis -y
    sudo chkconfig redis on
    sudo sed -i 's/^bind/#bind/' /etc/redis.conf
    sudo service redis restart
"""
    res = ec2conn.run_instances('ami-ea26ce85', min_count=noofservers, max_count=noofservers, key_name=keyname, instance_type='t2.micro', security_group_ids=[sgid], subnet_id=subnetid, user_data = base64.b64encode(code_to_install_redis))
    c = 0
    ip = ""
    ip_priv = ""
    for instance in res.instances:
        c += 1
        if c % 2 != 0:
            instance.add_tag('Name', "Redis-Master" + str(int(c/2+1)))
            instance.update()
            while instance.state != 'running':
                time.sleep(5)
                instance.update()
            if instance.ip_address:
                ip = instance.ip_address.public_ip
            else:
                ip = ec2conn.allocate_address()
                ec2conn.associate_address(instance_id=instance.id, allocation_id=ip.allocation_id)
            ip_priv = instance.private_ip_address
        else:
            instance.add_tag('Name', "Redis-Slave" + str(int(c/2)))
            instance.update()
            while instance.state != 'running':
                time.sleep(5)
                instance.update()
            if instance.ip_address:
                ip = instance.ip_address.public_ip
            else:
                ip = ec2conn.allocate_address()
                ec2conn.associate_address(instance_id=instance.id, allocation_id=ip.allocation_id)
            time.sleep(60)
            ssh = subprocess.Popen(["ssh", "-i", homedir + "/.ssh/" + nameofawskey + ".pem", "-o", "StrictHostKeyChecking=no", "-o", "CheckHostIP=no", "ec2-user@" + ip.public_ip, "sudo sed -i -e 's/^#.*slaveof.*<master.*/slaveof " + ip_priv +" 6379/' /etc/redis.conf ; sudo service redis restart" ],
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            result = ssh.stdout.readlines()
            if result == []:
                error = ssh.stderr.readlines()
                print >> sys.stderr, "ERROR: %s" % error



region = args.region
nameofawskey = args.key
numberofinstances = int(args.numberofreadisserrvers)
addr = args.cidr

ec2conn = boto.ec2.connect_to_region(region)
conn = boto.vpc.connect_to_region(region)
vpcs = conn.get_all_vpcs()
vpc_name = args.vpc
subnet_name = args.subnet

homedir = os.path.expanduser('~')
if not os.path.exists(homedir + "/.ssh/" + nameofawskey + ".pem"):
    key = create_key(nameofawskey)
else:
    key = ec2conn.get_key_pair(nameofawskey)

if not len(vpcs):
    if not addr:
        print "No VPC available...please use option -c (cidr address) to create a vpc automatically..."
        sys.exit()

    vpc = create_vpc_and_subnet(conn, addr)
    sg = create_sg(vpc)
    fs = {'vpc_id': vpc.id}
    subnet = conn.get_all_subnets(filters=fs)
    create_instances(key.name, sg.id, subnet[0].id, numberofinstances)
elif vpc_name:
    fs_vpc = {'tag:Name': vpc_name}
    vpcs = conn.get_all_vpcs(filters=fs_vpc)

    if len(vpcs):
        vpc = vpcs[0]
    else:
        print "No VPC available with name " + vpc_name
        sys.exit()

    fs_sub = {'tag:Name': subnet_name}
    if subnet_name:
        subnet = conn.get_all_subnets(filters=fs_sub)
    else:
        fs = {'vpc_id': vpc.id}
        subnet = conn.get_all_subnets(filters=fs)
        sid = subnet[0].id

    f = {'group-name': 'Redis'}
    sgg = ec2conn.get_all_security_groups(filters=f)

    if not len(sgg):
        sg = create_sg(vpc)
        sgid = sg.id
    else:
        for sg in sgg:
            if sg.vpc_id == vpc.id:
                sgid = sg.id

    create_instances(nameofawskey, sgid, sid, numberofinstances)

else:
    vpc = vpcs.pop(0)
    fs={'vpc_id': vpc.id}
    subnet = conn.get_all_subnets(filters=fs)
    sid = subnet[0].id
    f = {'group-name': 'Redis'}
    sgg = ec2conn.get_all_security_groups(filters=f)

    if not len(sgg):
        sg = create_sg(vpc)
        sgid = sg.id
    else:
        for sg in sgg:
            if sg.vpc_id == vpc.id:
                sgid = sg.id

    create_instances(nameofawskey, sgid, sid, numberofinstances)

