# aws-redis-python

Requirements:
- awscli/boto credentials(aws_access_key_id and aws_secret_access_key) should be set (E.g. .aws/credentials)
- python 2.7
- boto lib (pip install boto)

Usage:
./create_instance.py --help

This script creates Redis clusters in AWS

optional arguments:
  -h, --help            show this help message and exit
  -r REGION, --region REGION
                        The region where the instances will be created. E.g.
                        eu-central-1
  -n NUMBEROFREADISSERRVERS, --numberofreadisserrvers NUMBEROFREADISSERRVERS
                        Number of Redis servers that will be started
  -k KEY, --key KEY     The name of the key that will be used/created
  -v VPC, --vpc VPC     The name of vpc in which the instances will be
                        created; otherwise the default one will be used
  -s SUBNET, --subnet SUBNET
                        The name of subnet(in the vpc mentioned with -v param)
                        in which the instances will be created; otherwise the
                        default one will be used
  -c CIDR, --cidr CIDR  It will create a VPC with mask 24 and subnet 25

E.g.: ./create_instance.py -r eu-central-1 -n 2 -k tucel
