import boto3
import time
import logging
import os
import paramiko
log = logging.getLogger()
log.setLevel(logging.INFO)


region = 'us-east-1'
bucket_name = 'vktestboot'  # Bucket name
bucket_prefix = ""  # name of the Pri Key folder
prikey_name = 'prikey.pem'  # Prikey name
tag1 = "testtag"  # Both tag1 and tag2 ('VALUES' of tag, not 'KEY' ) must be present to identify the instance
tag2 = 'zzzz'
user = "ubuntu"  # username for the instances
comm = ['touch xyz1', 'touch xyz2', 'touch xyz3']  # Commands  to Execute
wait_time = 30  # Time to wait before working on next affected instance


def sshExec(conn, k):
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client = boto3.client('ec2', region)
    r = client.describe_instances(Filters=[
        {
            'Name': 'tag-value',
            'Values': [
                    tag1,
            ],
        }, {
            'Name': 'tag-value',
            'Values': [
                    tag2,
            ],
        }
    ],)

    log.info("List of all the instances  %s", r['Reservations'])
    l = len(r['Reservations'])
    for i in r['Reservations']:
        try:
            log.info('Connecting to PrivateIpAddress %s', i['Instances'][0]['PrivateIpAddress'])
            conn.connect(hostname=i['Instances'][0]['PrivateIpAddress'], username=user, pkey=k)
            PubKeyAuth = True
        except paramiko.ssh_exception.AuthenticationException:
            log.error("PubKey Authentication Failed! Connecting with password")
            conn.connect(hostname=i['PublicIpAddress'], username=user, password='PASSWORD')
            PubKeyAuth = False
        for j in comm:
            log.info("Executing command -> %s", j)
            conn.exec_command(j)
        l -= 1
        if l != 0:
            log.info("Will wait for %s seconds before working on next instance", wait_time)
            time.sleep(wait_time)


def downloadPrivateKey(bucket_name, bucket_prefix, region, prikey_name):
    if os.path.exists('/tmp/' + prikey_name):
        os.remove('/tmp/' + prikey_name)
    s3 = boto3.client('s3')
    log.info("Downloading Private Key")
    s3.download_file(bucket_name, bucket_prefix + prikey_name, "/tmp/" + prikey_name)


def lambda_handler(event, context):
    log.info('Received event %s', event)
    log.info('Received context %s', context)
    downloadPrivateKey(bucket_name, bucket_prefix, region, prikey_name)
    log.info('Downloaded Private key')
    k = paramiko.RSAKey.from_private_key_file("/tmp/" + prikey_name)
    conn = paramiko.SSHClient()
    log.info('Will execute SSH commands now')
    sshExec(conn, k)
