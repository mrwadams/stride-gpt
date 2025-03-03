import requests
import json
import unittest
from unittest.mock import patch, MagicMock
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
import streamlit as st

import google.generativeai as genai
from groq import Groq
from utils import process_groq_response, create_reasoning_system_prompt

# Import the module with Bedrock implementation
from threat_model import get_threat_model_bedrock

# Function to create a prompt to generate mitigating controls
def create_test_cases_prompt(threats):
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology. 
Your task is to provide Gherkin test cases for the threats identified in a threat model. It is very important that 
your responses are tailored to reflect the details of the threats. 

Below is the list of identified threats:
{threats}

Use the threat descriptions in the 'Given' steps so that the test cases are specific to the threats identified.
Put the Gherkin syntax inside triple backticks (```) to format the test cases in Markdown. Add a title for each test case.
For example:

    ```gherkin
    Given a user with a valid account
    When the user logs in
    Then the user should be able to access the system
    ```

YOUR RESPONSE (do not add introductory text, just provide the Gherkin test cases):
"""
    return prompt


# Function to get test cases from the GPT response.
def get_test_cases(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3-mini), use a structured system prompt
    if model_name in ["o1", "o3-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Generate comprehensive security test cases in Gherkin format for the identified threats.",
            approach_description="""1. Analyze each threat in the provided threat model:
   - Understand the threat type and scenario
   - Identify critical security aspects to test
   - Consider both positive and negative test cases
2. For each test case:
   - Write clear preconditions in 'Given' steps
   - Define specific actions in 'When' steps
   - Specify expected outcomes in 'Then' steps
   - Include relevant security validation checks
3. Structure the test cases:
   - Add descriptive titles for each scenario
   - Use proper Gherkin syntax and formatting
   - Group related test cases together
   - Include edge cases and boundary conditions
4. Format output as Markdown with Gherkin code blocks:
   - Use proper code block syntax
   - Ensure consistent indentation
   - Add clear scenario descriptions"""
        )
        # Create completion with max_completion_tokens for o1/o3-mini
        response = client.chat.completions.create(
            model = model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_completion_tokens=4000
        )
    else:
        system_prompt = "You are a helpful assistant that provides Gherkin test cases in Markdown format."
        # Create completion with max_tokens for other models
        response = client.chat.completions.create(
            model = model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000
        )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get mitigations from the Azure OpenAI response.
def get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from the Google model's response.
def get_test_cases_google(google_api_key, google_model, prompt):
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel(
        google_model,
        system_instruction="You are a helpful assistant that provides Gherkin test cases in Markdown format.",
    )
    response = model.generate_content(prompt)
    
    # Access the content directly as the response will be in text format
    test_cases = response.candidates[0].content.parts[0].text

    return test_cases

# Function to get test cases from the Mistral model's response.
def get_test_cases_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model = mistral_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from Ollama hosted LLM.
def get_test_cases_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get test cases from Ollama hosted LLM.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model
        
    Returns:
        str: The generated test cases in markdown format
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """You are a cyber security expert with more than 20 years experience of security testing applications. Your task is to analyze the provided application description and suggest appropriate security test cases.

Please provide your response in markdown format with appropriate headings and bullet points. For each test case, include:
- Test objective
- Prerequisites
- Test steps
- Expected results
- Pass/fail criteria"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()
        
        try:
            # Access the 'content' attribute of the 'message' dictionary
            test_cases = outer_json["message"]["content"]
            return test_cases
            
        except KeyError as e:
            print(f"Error accessing response fields: {str(e)}")
            print("Raw response:", outer_json)
            raise
            
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with Ollama endpoint: {str(e)}")
        raise

# Function to get test cases from the Anthropic model's response.
def get_test_cases_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)
    response = client.messages.create(
        model=anthropic_model,
        max_tokens=4096,
        system="You are a helpful assistant that provides Gherkin test cases in Markdown format.",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    # Access the text content from the first content block
    test_cases = response.content[0].text

    return test_cases

# Function to get test cases from LM Studio Server response.
def get_test_cases_lm_studio(lm_studio_endpoint, model_name, prompt):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from the Groq model's response.
def get_test_cases_groq(groq_api_key, groq_model, prompt):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, test_cases = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=False
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return test_cases

class TestBedrockIntegration(unittest.TestCase):
    """Test suite for Amazon Bedrock integration."""

    def setUp(self):
        """Set up test fixtures."""
        # Common test data
        self.aws_access_key = "test_access_key"
        self.aws_secret_key = "test_secret_key"
        self.aws_region = "us-east-1"
        self.prompt = "Test prompt for threat model generation"
        
        # Mock streamlit session state
        if not hasattr(st, "session_state"):
            st.session_state = {}

    @patch('boto3.Session')
    def test_bedrock_client_creation(self, mock_session):
        """Test that the Bedrock client is created with the correct parameters."""
        # Create mock objects
        mock_bedrock_client = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_bedrock_client
        
        # Configure mock to return a valid response structure to avoid processing errors
        mock_response = {
            'body': MagicMock(),
        }
        mock_response['body'].read.return_value = json.dumps({'content': [{'text': '{}'}]}).encode('utf-8')
        mock_bedrock_client.invoke_model.return_value = mock_response
        
        # Call the function (it will fail with an error, but we're just testing the client creation)
        try:
            get_threat_model_bedrock(
                self.aws_access_key, 
                self.aws_secret_key, 
                self.aws_region, 
                'anthropic.claude-3-sonnet-20240229-v1:0',
                self.prompt
            )
        except Exception:
            pass
        
        # Assert that session was created with correct parameters
        mock_session.assert_called_once_with(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        
        # Assert that client was created with correct service name
        mock_session_instance.client.assert_called_once_with('bedrock-runtime')

    @patch('boto3.Session')
    def test_anthropic_request_format(self, mock_session):
        """Test that requests for Anthropic models are formatted correctly."""
        # Create mock objects
        mock_bedrock_client = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_bedrock_client
        
        # Configure mock to return a valid response
        mock_response = {
            'body': MagicMock(),
        }
        mock_response['body'].read.return_value = json.dumps({'content': [{'text': '{}'}]}).encode('utf-8')
        mock_bedrock_client.invoke_model.return_value = mock_response
        
        # Call the function with an Anthropic model
        model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        get_threat_model_bedrock(
            self.aws_access_key, 
            self.aws_secret_key, 
            self.aws_region, 
            model_id,
            self.prompt
        )
        
        # Assert that invoke_model was called with the correct parameters
        args, kwargs = mock_bedrock_client.invoke_model.call_args
        
        # Check model ID
        self.assertEqual(kwargs['modelId'], model_id)
        
        # Check request body format for Anthropic
        request_body = json.loads(kwargs['body'])
        self.assertEqual(request_body['anthropic_version'], 'bedrock-2023-05-31')
        self.assertEqual(request_body['max_tokens'], 4096)
        self.assertEqual(request_body['system'], 'You are a helpful assistant designed to output JSON.')
        self.assertEqual(request_body['messages'][0]['role'], 'user')
        self.assertEqual(request_body['messages'][0]['content'], self.prompt)
        self.assertEqual(request_body['response_format']['type'], 'json_object')

    @patch('boto3.Session')
    def test_amazon_request_format(self, mock_session):
        """Test that requests for Amazon Titan models are formatted correctly."""
        # Create mock objects
        mock_bedrock_client = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_bedrock_client
        
        # Configure mock to return a valid response
        mock_response = {
            'body': MagicMock(),
        }
        mock_response['body'].read.return_value = json.dumps({'results': [{'outputText': '{}'}]}).encode('utf-8')
        mock_bedrock_client.invoke_model.return_value = mock_response
        
        # Call the function with an Amazon Titan model
        model_id = 'amazon.titan-text-express-v1'
        get_threat_model_bedrock(
            self.aws_access_key, 
            self.aws_secret_key, 
            self.aws_region, 
            model_id,
            self.prompt
        )
        
        # Assert that invoke_model was called with the correct parameters
        args, kwargs = mock_bedrock_client.invoke_model.call_args
        
        # Check model ID
        self.assertEqual(kwargs['modelId'], model_id)
        
        # Check request body format for Amazon Titan
        request_body = json.loads(kwargs['body'])
        self.assertEqual(request_body['inputText'], f'You are a helpful assistant designed to output JSON.\n\n{self.prompt}')
        
        # Check max token count based on model type
        self.assertEqual(request_body['textGenerationConfig']['maxTokenCount'], 8192)

    @patch('boto3.Session')
    def test_error_handling(self, mock_session):
        """Test that errors are handled properly."""
        # Create mock objects
        mock_bedrock_client = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_bedrock_client
        
        # Configure mock to raise an error
        error_response = {
            'Error': {
                'Code': 'AccessDeniedException',
                'Message': 'Access denied'
            }
        }
        mock_bedrock_client.invoke_model.side_effect = ClientError(error_response, 'InvokeModel')
        
        # Patch st.error to catch the error message
        with patch('streamlit.error') as mock_st_error:
            # Call the function
            result = get_threat_model_bedrock(
                self.aws_access_key, 
                self.aws_secret_key, 
                self.aws_region, 
                'anthropic.claude-3-sonnet-20240229-v1:0',
                self.prompt
            )
            
            # Assert that st.error was called with the error message
            mock_st_error.assert_called_once()
            
            # Assert that the function returns a valid fallback structure
            self.assertIn('threat_model', result)
            self.assertIn('improvement_suggestions', result)
            self.assertEqual(len(result['threat_model']), 0)
            self.assertEqual(len(result['improvement_suggestions']), 2)

    @patch('boto3.Session')
    def test_json_response_parsing(self, mock_session):
        """Test that JSON responses are parsed correctly."""
        # Create mock objects
        mock_bedrock_client = MagicMock()
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_bedrock_client
        
        # Example threat model response
        threat_model_response = {
            'threat_model': [
                {
                    'Threat Type': 'Spoofing',
                    'Scenario': 'Test scenario',
                    'Potential Impact': 'Test impact'
                }
            ],
            'improvement_suggestions': [
                'Test suggestion'
            ]
        }
        
        # Configure mock to return a valid response for Claude
        mock_response = {
            'body': MagicMock(),
        }
        mock_response['body'].read.return_value = json.dumps({
            'content': [{'text': json.dumps(threat_model_response)}]
        }).encode('utf-8')
        mock_bedrock_client.invoke_model.return_value = mock_response
        
        # Call the function with a Claude model
        result = get_threat_model_bedrock(
            self.aws_access_key, 
            self.aws_secret_key, 
            self.aws_region, 
            'anthropic.claude-3-sonnet-20240229-v1:0',
            self.prompt
        )
        
        # Assert that the function returns the expected result
        self.assertEqual(result, threat_model_response)
        self.assertEqual(len(result['threat_model']), 1)
        self.assertEqual(result['threat_model'][0]['Threat Type'], 'Spoofing')
        self.assertEqual(len(result['improvement_suggestions']), 1)