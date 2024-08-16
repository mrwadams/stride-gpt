import json
import google.generativeai as genai
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
from openai import OpenAI
from openai import AzureOpenAI
from anthropic import Anthropic

import streamlit as st

def dread_json_to_markdown(dread_assessment):
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|-------------|----------|------------------|-----------------|----------------|----------------|-----------------|-------------|\n"
    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])
        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                damage_potential = threat.get('Damage Potential', 0)
                reproducibility = threat.get('Reproducibility', 0)
                exploitability = threat.get('Exploitability', 0)
                affected_users = threat.get('Affected Users', 0)
                discoverability = threat.get('Discoverability', 0)
                
                # Calculate the Risk Score
                risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5
                
                markdown_output += f"| {threat.get('Threat Type', 'N/A')} | {threat.get('Scenario', 'N/A')} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                raise TypeError(f"Expected a dictionary, got {type(threat)}: {threat}")
    except Exception as e:
        # Print the error message and type for debugging
        st.write(f"Error: {e}")
        raise
    return markdown_output


# Function to create a prompt to generate mitigating controls
def create_dread_assessment_prompt(threats):
    prompt = f"""
Act as a cyber security expert with more than 20 years of experience in threat modeling using STRIDE and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model.
Below is the list of identified threats:
{threats}
When providing the risk assessment, use a JSON formatted response with a top-level key "Risk Assessment" and a list of threats, each with the following sub-keys:
- "Threat Type": A string representing the type of threat (e.g., "Spoofing").
- "Scenario": A string describing the threat scenario.
- "Damage Potential": An integer between 1 and 10.
- "Reproducibility": An integer between 1 and 10.
- "Exploitability": An integer between 1 and 10.
- "Affected Users": An integer between 1 and 10.
- "Discoverability": An integer between 1 and 10.
Assign a value between 1 and 10 for each sub-key based on the DREAD methodology. Use the following scale:
- 1-3: Low
- 4-6: Medium
- 7-10: High
Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "Risk Assessment": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could create a fake OAuth2 provider and trick users into logging in through it.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could intercept the OAuth2 token exchange process through a Man-in-the-Middle (MitM) attack.",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
"""
    return prompt

# Function to get DREAD risk assessment from the GPT response.
def get_dread_assessment(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )
    
    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        st.write(f"JSON decoding error: {e}")
        dread_assessment = {}
    
    return dread_assessment

# Function to get DREAD risk assessment from the Azure OpenAI response.
def get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        st.write(f"JSON decoding error: {e}")
        dread_assessment = {}
    
    return dread_assessment

# Function to get DREAD risk assessment from the Google model's response.
def get_dread_assessment_google(google_api_key, google_model, prompt):
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel(
        google_model,
        generation_config={"response_mime_type": "application/json"})
    response = model.generate_content(prompt)
    try:
        # Access the JSON content from the 'parts' attribute of the 'content' object
        response_content = json.loads(response.candidates[0].content.parts[0].text)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {str(e)}")
        print("Raw JSON string:")
        print(response.candidates[0].content.parts[0].text)
        return None

    return response_content

# Function to get DREAD risk assessment from the Mistral model's response.
def get_dread_assessment_mistral(mistral_api_key, mistral_model, prompt):
    client = MistralClient(api_key=mistral_api_key)

    response = client.chat(
        model = mistral_model,
        response_format={"type": "json_object"},
        messages=[
            ChatMessage(role="user", content=prompt)
        ]
    )

    # Access the content directly as the response will be in text format
    response_content = response.content[0].text

    return response_content

# Function to get DREAD risk assessment from the Claude model's response.
def get_dread_assessment_claude(claude_api_key, claude_model, prompt):
    client = Anthropic(api_key=claude_api_key)
    response = client.messages.create(
        model=claude_model,
        max_tokens=1024,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    response_content = response.content[0].text

    return response_content