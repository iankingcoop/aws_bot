"""
simple agent with langchain, boto3, and openai
"""

import os
import boto3
from botocore.exceptions import ClientError

from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI


### tools to be called by the agent user the @tool decorator
@tool
def list_s3_buckets(query: str = "") -> str:
    """Lists all S3 buckets in the AWS account. 
    Call this when the user asks about S3 buckets, how many buckets exist, 
    or wants to see bucket names."""
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        if not buckets:
            return "No S3 buckets found in this account."
        
        result = f"Found {len(buckets)} S3 buckets:\n"
        for bucket in buckets:
            result += f"  - {bucket['Name']}\n"
        
        return result
        
    except ClientError as e:
        return f"Error accessing S3: {e.response['Error']['Message']}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


### init agent
def create_simple_agent():
    
    agent = create_agent(
        model="gpt-3.5-turbo", # cheaper than latest
        tools=[
            list_s3_buckets,
            get_s3_bucket_contents,
            check_public_s3_buckets,
            get_ec2_instance_size,
            get_iam_user_permissions
        ],
        system_prompt="""You are a security/infratructure assistant. 
        When users ask about AWS resources, use the tools provided to gather information.
        Provide clear, concise answers based on the tool results."""
    )
    
    return agent


@tool
def get_s3_bucket_contents(bucket_name: str) -> str:
    """Gets detailed information about what data an S3 bucket holds.
    Use this when the user asks about the contents of a specific bucket or
    if they want to know if a bucket contains sensitive data.
    
    Args:
        bucket_name: The name of the S3 bucket to inspect
    """
    try:
        s3 = boto3.client('s3')
        
        # List objects in the bucket
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
        
        if 'Contents' not in response:
            return f"Bucket '{bucket_name}' is empty or doesn't exist."
        
        objects = response['Contents']
        total_size = sum(obj['Size'] for obj in objects)
        
        def format_size(size_bytes):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.2f} PB"
        
        result = f"Bucket: {bucket_name}\n"
        result += f"Total objects: {len(objects)}\n"
        result += f"Total size: {format_size(total_size)}\n\n"
        result += "Sample objects:\n"
        
        for obj in objects[:10]:
            result += f"  - {obj['Key']} ({format_size(obj['Size'])})\n"
        
        if len(objects) > 10:
            result += f"  ... and {len(objects) - 10} more objects\n"
        
        # Check for potentially sensitive data
        sensitive_keywords = ['password', 'secret', 'key']
        sensitive_files = []
        
        for obj in objects:
            key = obj['Key']
            for keyword in sensitive_keywords:
                if keyword in key.lower():
                    sensitive_files.append(key)
                    break
        
        if sensitive_files:
            result += f"\nWARNING: Found {len(sensitive_files)} potentially sensitive files:\n"
            for file in sensitive_files[:5]:
                result += f"  - {file}\n"
        
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            return f"Bucket '{bucket_name}' does not exist."
        elif error_code == 'AccessDenied':
            return f"Access denied to bucket '{bucket_name}'."
        return f"Error accessing bucket: {e.response['Error']['Message']}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


@tool
def get_ec2_instance_size(ip_address: str) -> str:
    """Gets the size/type of an EC2 instance by its IP address.
    Use this when the user asks about an EC2 instance's size, type, or specifications.
    
    Args:
        ip_address: The IP address of the EC2 instance (can be private or public)
    """
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # search private IP
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'private-ip-address', 'Values': [ip_address]},
            ]
        )
        
        # otherwise search by public IP
        if not response['Reservations']:
            response = ec2.describe_instances(
                Filters=[
                    {'Name': 'ip-address', 'Values': [ip_address]},
                ]
            )
        
        if not response['Reservations']:
            return f"No EC2 instance found with IP address {ip_address}"
        
        instance = response['Reservations'][0]['Instances'][0]
        instance_type = instance['InstanceType']
        instance_id = instance['InstanceId']
        state = instance['State']['Name']
        
        result = f"EC2 Instance Details:\n"
        result += f"Instance ID: {instance_id}\n"
        result += f"Instance Type: {instance_type}\n"
        result += f"State: {state}\n"
        result += f"IP Address: {ip_address}\n"
        
        # Add some context about the instance size
        if 'nano' in instance_type:
            result += "size- very small\n"
        elif 'micro' in instance_type or 'small' in instance_type:
            result += "size- small\n"
        elif 'medium' in instance_type:
            result += "size- medium\n"
        elif 'large' in instance_type:
            result += "size- large\n"
        elif 'xlarge' in instance_type:
            result += "size- extra large\n"
        
        return result
        
    except ClientError as e:
        return f"Error finding EC2 instance: {e.response['Error']['Message']}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


@tool
def get_iam_user_permissions(username: str) -> str:
    """Gets the permissions and policies attached to an IAM user.
    Use this when the user asks about what permissions or access an IAM user has.
    
    Args:
        username: The IAM username to look up
    """
    try:
        iam = boto3.client('iam')
        
        result = f"IAM User: {username}\n\n"
        
        # Get attached managed policies
        try:
            attached_policies = iam.list_attached_user_policies(UserName=username)
            
            if attached_policies['AttachedPolicies']:
                result += "Attached Managed Policies:\n"
                for policy in attached_policies['AttachedPolicies']:
                    result += f"  - {policy['PolicyName']}\n"
            else:
                result += "No attached managed policies.\n"
        except Exception as e:
            result += f"Could not retrieve attached policies: {str(e)}\n"
        
        # Get inline policies
        try:
            inline_policies = iam.list_user_policies(UserName=username)
            
            if inline_policies['PolicyNames']:
                result += "\nInline Policies:\n"
                for policy_name in inline_policies['PolicyNames']:
                    result += f"  - {policy_name}\n"
            else:
                result += "\nNo inline policies.\n"
        except Exception as e:
            result += f"\nCould not retrieve inline policies: {str(e)}\n"
        
        # Get groups
        try:
            groups = iam.list_groups_for_user(UserName=username)
            
            if groups['Groups']:
                result += "\nGroup Memberships:\n"
                for group in groups['Groups']:
                    result += f"  - {group['GroupName']}\n"
                result += "\n(User inherits permissions from these groups)\n"
            else:
                result += "\nNo group memberships.\n"
        except Exception as e:
            result += f"\nCould not retrieve groups: {str(e)}\n"
        
        if not attached_policies['AttachedPolicies'] and not inline_policies['PolicyNames']:
            result += "\nNote: User has no direct policies. Check group memberships for inherited permissions.\n"
        
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            return f"IAM user '{username}' does not exist."
        return f"Error: {e.response['Error']['Message']}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@tool
def check_public_s3_buckets(query: str = "") -> str:
    """Checks which S3 buckets are exposed to the public.
    Use this when the user asks about public buckets or bucket security."""
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        public_buckets = []
        total_buckets = len(buckets)
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Check bucket policy status
                policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
                is_public = policy_status['PolicyStatus']['IsPublic']
                
                if is_public:
                    public_buckets.append(bucket_name)
            except ClientError as e:
                # If no policy, check ACL
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                                public_buckets.append(bucket_name)
                                break
                    except:
                        pass
        
        result = f"Total S3 buckets: {total_buckets}\n"
        result += f"Public buckets: {len(public_buckets)}\n"
        
        if public_buckets:
            result += f"\nWARNING: These buckets are publicly accessible:\n"
            for bucket in public_buckets:
                result += f"  - {bucket}\n"
        else:
            result += "\nNo public buckets found."
        
        return result
        
    except Exception as e:
        return f"Error checking bucket security: {str(e)}"


@tool
def get_s3_bucket_contents(bucket_name: str) -> str:
    """Gets detailed information about what data an S3 bucket holds, including analyzing file contents.
    Use this when the user asks about the contents of a specific bucket or sensitive data.
    
    Args:
        bucket_name: The name of the S3 bucket to inspect
    """
    try:
        s3 = boto3.client('s3')
        
        # List objects in the bucket
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
        
        if 'Contents' not in response:
            return f"Bucket '{bucket_name}' is empty or doesn't exist."
        
        objects = response['Contents']
        total_size = sum(obj['Size'] for obj in objects)
        
        # Format size nicely
        def format_size(size_bytes):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.2f} PB"
        
        result = f"Bucket: {bucket_name}\n"
        result += f"Total objects: {len(objects)}\n"
        result += f"Total size: {format_size(total_size)}\n\n"
        result += "Objects in bucket:\n"
        
        # Analyze each file
        sensitive_files = []
        file_types = {}
        
        for obj in objects[:20]:  # Analyze first 20 files
            key = obj['Key']
            size = obj['Size']
            result += f"  - {key} ({format_size(size)})\n"
            
            # Track file types
            ext = key.split('.')[-1].lower() if '.' in key else 'no_extension'
            file_types[ext] = file_types.get(ext, 0) + 1
            
            # Check filename for sensitive keywords
            sensitive_keywords = ['password', 'secret', 'key', 'credential', 'token', 
                                 'private', 'confidential', 'ssn', 'credit', 'database',
                                 'backup', 'dump', 'export', 'api', 'auth']
            
            if any(keyword in key.lower() for keyword in sensitive_keywords):
                sensitive_files.append(key)
            
            # Read text files to check contents
            if ext in ['txt', 'log', 'json', 'csv', 'xml', 'yaml', 'yml', 'conf', 'config', 'env']:
                try:
                    obj_response = s3.get_object(Bucket=bucket_name, Key=key)
                    content = obj_response['Body'].read().decode('utf-8', errors='ignore')[:5000]
                    
                    # Check content for sensitive patterns
                    sensitive_patterns = [
                        'password', 'api_key', 'secret', 'token', 'credential',
                        'aws_access_key', 'aws_secret', 'private_key',
                        'ssn', 'social security', 'credit card', 'card number'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern.replace('_', ' ') in content.lower() or pattern in content.lower():
                            if key not in sensitive_files:
                                sensitive_files.append(f"{key} (contains: {pattern})")
                            break
                    
                except Exception as e:
                    pass
        
        if len(objects) > 20:
            result += f"  ... and {len(objects) - 20} more objects\n"
        
        # Security warnings
        if sensitive_files:
            result += f"\nWARNING: Found {len(sensitive_files)} potentially sensitive files:\n"
            for file in sensitive_files[:10]:
                result += f"  - {file}\n"
            if len(sensitive_files) > 10:
                result += f"  ... and {len(sensitive_files) - 10} more\n"
        else:
            result += f"\nNo obviously sensitive files detected in filenames or contents.\n"
        
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            return f"Bucket '{bucket_name}' does not exist."
        elif error_code == 'AccessDenied':
            return f"Access denied to bucket '{bucket_name}'. Check permissions."
        return f"Error accessing bucket: {e.response['Error']['Message']}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def main():
    # Check for OpenAI API key
    if not os.environ.get('OPENAI_API_KEY'):
        return
    
    # Check for AWS credentials
    try:
        boto3.client('sts').get_caller_identity()
    except Exception as e:
        return
    
    try:
        agent = create_simple_agent()
    except Exception as e:
        return
    
    # Test questions
    sample_questions = [
        "how many S3 buckets do i have?",
        "list all my S3 buckets",
        "what data does the S3 bucket aws-bot-demo-12314 hold?",
        "does the bucket aws-bot-demo-12314 contain any sensitive data?",
        "what permissions does user aws_bot_user have?",
        "tell me about the ec2 instance at 172.31.24.193"
    ]
    
    # Open output file
    with open('sample_output.txt', 'w') as f:
        f.write("testing agent with sample questions:\n")
        f.write("-" * 60 + "\n")
        
        print("testing agent with sample questions:")
        print("-" * 60)
        
        for question in sample_questions:
            output = f"\n{'-'*60}\nQuestion: {question}\n{'-'*60}\n"
            f.write(output)
            print(output, end='')
            
            try:
                response = agent.invoke({
                    "messages": [{"role": "user", "content": question}]
                })
                
                final_message = response["messages"][-1].content
                result = f"\nResults: {final_message}\n\n"
                f.write(result)
                print(result, end='')
                
            except Exception as e:
                error = f"\nError: {str(e)}\n\n"
                f.write(error)
                print(error, end='')
    
    print("\n" + "-" * 60)
    print("What else would you like to know?")
    print("-" * 60)
    
    while True:
        try:
            question = input("\nYour question: ").strip()
            
            if not question:
                continue
            
            response = agent.invoke({
                "messages": [{"role": "user", "content": question}]
            })
            
            final_message = response["messages"][-1].content
            print(f"\nResults: {final_message}")
            
        except Exception as e:
            print(f"\nError: {str(e)}")


if __name__ == "__main__":
    main()