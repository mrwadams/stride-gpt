"""
Example usage of Amazon Bedrock integration for STRIDE GPT.

This script demonstrates how to use the Amazon Bedrock integration
to generate a threat model for a simple application.

To run this example:
1. Set up your AWS credentials in environment variables or AWS config file
2. Install required packages: pip install -r requirements.txt
3. Run: python example_bedrock_usage.py
"""

import os
import json
from threat_model import get_threat_model_bedrock, create_threat_model_prompt, json_to_markdown

def main():
    """Run the example."""
    # Get AWS credentials from environment variables
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')

    if not aws_access_key or not aws_secret_key:
        print("AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")
        return

    # Example application details
    app_type = "Web application"
    authentication = ["OAUTH2", "MFA"]
    internet_facing = "Yes"
    sensitive_data = "Confidential"
    app_input = """
    A web application that allows users to create, store, and share personal notes.
    The application is built using the React frontend framework and a Node.js backend with a MongoDB database.
    Users can sign up for an account and log in using OAuth2 with Google or Facebook.
    The notes are encrypted at rest and are only accessible by the user who created them.
    The application also supports real-time collaboration on notes with other users.
    """

    # Create the threat model prompt
    threat_model_prompt = create_threat_model_prompt(
        app_type, authentication, internet_facing, sensitive_data, app_input
    )

    # Set the Bedrock model to use
    # Use one of the models you have access to in your AWS account
    bedrock_model = "anthropic.claude-3-sonnet-20240229-v1:0"  # Example model, may need to change

    print(f"Generating threat model using Amazon Bedrock model: {bedrock_model}")
    print("This may take a minute or two...")

    try:
        # Generate the threat model
        model_output = get_threat_model_bedrock(
            aws_access_key,
            aws_secret_key,
            aws_region,
            bedrock_model,
            threat_model_prompt
        )

        # Access the threat model and improvement suggestions from the parsed content
        threat_model = model_output.get("threat_model", [])
        improvement_suggestions = model_output.get("improvement_suggestions", [])

        # Convert to markdown for display
        markdown_output = json_to_markdown(threat_model, improvement_suggestions)

        # Print the results
        print("\n\n=== Threat Model Results ===\n")
        print(markdown_output)

        # Save to file
        with open("bedrock_threat_model_example.md", "w") as f:
            f.write(markdown_output)
        print("\nResults saved to bedrock_threat_model_example.md")

    except Exception as e:
        print(f"Error generating threat model: {e}")

if __name__ == "__main__":
    main()