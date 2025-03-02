"""
Test cases for Amazon Bedrock integration.

This module contains unit tests for the Amazon Bedrock integration in STRIDE GPT.

To run tests:
    python -m unittest test_bedrock.py

Or run with more details:
    python -m unittest -v test_bedrock.py
"""

import unittest
import json
from unittest.mock import patch, MagicMock
import boto3
from botocore.exceptions import ClientError, BotoCoreError
import streamlit as st

# Import the module with our Bedrock implementation
from threat_model import get_threat_model_bedrock

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
        if 'premier' in model_id.lower():
            self.assertEqual(request_body['textGenerationConfig']['maxTokenCount'], 3072)
        else:
            self.assertEqual(request_body['textGenerationConfig']['maxTokenCount'], 4096)
            
        # Only check responseFormatOptions if it's an Express model (not Premier)
        if 'premier' not in model_id.lower():
            self.assertEqual(request_body['textGenerationConfig']['responseFormatOptions']['type'], 'JSON')

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


if __name__ == '__main__':
    unittest.main()