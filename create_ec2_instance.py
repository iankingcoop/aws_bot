"""
simple script to create a tiny EC2 instance for testing
"""

import boto3

def create_tiny_ec2():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    response = ec2.run_instances(
        ImageId='ami-0023921b4fcd5382b',
        InstanceType='t2.micro',
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': 'aws-bot-test-instance'},
                    {'Key': 'Purpose', 'Value': 'testing'}
                ]
            }
        ]
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    print(f"Created instance: {instance_id}")
    print(f"Instance type: t2.micro")
    print(f"Waiting for instance to start...")
    
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    
    instances = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instances['Reservations'][0]['Instances'][0]
    
    private_ip = instance.get('PrivateIpAddress', 'N/A')
    public_ip = instance.get('PublicIpAddress', 'N/A')
    
    print(f"\nInstance is running!")
    print(f"Instance ID: {instance_id}")
    print(f"Private IP: {private_ip}")
    print(f"Public IP: {public_ip}")
    print(f"\nTo terminate: aws ec2 terminate-instances --instance-ids {instance_id}")
    
    return instance_id

if __name__ == "__main__":
    create_tiny_ec2()
