import google.generativeai as genai
from mistralai.client import MistralClient
from openai import OpenAI
from openai import AzureOpenAI

# Function to create a prompt to generate mitigating controls
def create_test_cases_prompt(threats):
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology. 
Your task is to provide Gherkin test cases for the threats identified in a threat model. It is very important that 
your responses are tailored to reflect the details of the threats. 

Below is the list of identified threats:
{threats}

Use the threat descriptions in the 'Given' steps so that the test cases are specific to the threats identified.

YOUR RESPONSE (do not wrap in a code block):
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


# TODO: Update the following functions to generate test cases.

# Function to get mitigations from the Azure OpenAI response.
def get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations

# Function to get mitigations from the Google model's response.
def get_mitigations_google(google_api_key, google_model, prompt):
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel(
        google_model,
        system_instruction="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
    )
    response = model.generate_content(prompt)
    try:
        # Extract the text content from the 'candidates' attribute
        mitigations = response.candidates[0].content.parts[0].text
        # Replace '\n' with actual newline characters
        mitigations = mitigations.replace('\\n', '\n')
    except (IndexError, AttributeError) as e:
        print(f"Error accessing response content: {str(e)}")
        print("Raw response:")
        print(response)
        return None

    return mitigations

# Function to get mitigations from the Mistral model's response.
def get_mitigations_mistral(mistral_api_key, mistral_model, prompt):
    client = MistralClient(api_key=mistral_api_key)

    response = client.chat(
        model = mistral_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations