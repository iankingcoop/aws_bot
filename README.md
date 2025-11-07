# AWS Bot

Natural language chatbot that is capable of answering questions about an AWS account.

## Requirements

- Python 3.8+
- AWS credentials configured (`aws configure`)
- OpenAI API key set as environment variable

```bash
export OPENAI_API_KEY=your_key_here
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python aws_security_bot.py
```

## Available Tools

The bot can answer questions about:

- **S3 Buckets** - List all buckets, view bucket contents, check for public buckets
- **EC2 Instances** - Get instance details by IP address
- **IAM Users** - View user permissions and policies
- **Security Analysis** - Detect potentially sensitive files in S3 buckets

## Example Questions

- "How many S3 buckets do I have?"
- "Is there any sensitive information in my S3 bucket?"
- "Are any of my S3 buckets public?"
- "What permissions does user bob have?"
- "What size is the EC2 instance with IP 10xxx?"
