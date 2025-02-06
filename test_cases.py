import requests
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
import streamlit as st

import google.generativeai as genai
from groq import Groq
from utils import process_groq_response

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

    response = client.chat.completions.create(
        model = model_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
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