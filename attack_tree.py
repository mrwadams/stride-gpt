import re
from mistralai import Mistral
from openai import OpenAI
from openai import AzureOpenAI
from anthropic import Anthropic

# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}
"""
    return prompt


# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

```mermaid
graph TD
    A[Enter Chart Definition] --> B(Preview)
    B --> C{{decide}}
    C --> D["Keep"]
    C --> E["Edit Definition (Edit)"]
    E --> B
    D --> F["Save Image and Code"]
    F --> B
```

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].
"""},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the 'content' attribute of the 'message' object directly
    attack_tree_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code

# Function to get attack tree from the Azure OpenAI response.
def get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

```mermaid
graph TD
    A[Enter Chart Definition] --> B(Preview)
    B --> C{{decide}}
    C --> D["Keep"]
    C --> E["Edit Definition (Edit)"]
    E --> B
    D --> F["Save Image and Code"]
    F --> B
```

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].
"""},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the 'content' attribute of the 'message' object directly
    attack_tree_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code

# Function to get attack tree from the Mistral model's response.
def get_attack_tree_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        messages=[
            {"role": "system", "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

```mermaid
graph TD
    A[Enter Chart Definition] --> B(Preview)
    B --> C{{decide}}
    C --> D["Keep"]
    C --> E["Edit Definition (Edit)"]
    E --> B
    D --> F["Save Image and Code"]
    F --> B
```

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].
"""},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the 'content' attribute of the 'message' object directly
    attack_tree_code = response.choices[0].message.content
    
    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code


# Function to get attack tree from the Mistral model's response.
def get_attack_tree_claude(claude_api_key, claude_model, prompt):
    client = Anthropic(api_key=claude_api_key)

    response = client.messages.create(
        model=claude_model,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": """
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax. The attack tree should reflect the potential threats for the application based on the details given.

You MUST only respond with the Mermaid code block. See below for a simple example of the required format and syntax for your output.

```mermaid
graph TD
    A[Enter Chart Definition] --> B(Preview)
    B --> C{{decide}}
    C --> D["Keep"]
    C --> E["Edit Definition (Edit)"]
    E --> B
    D --> F["Save Image and Code"]
    F --> B
```

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].
"""},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the 'content' attribute of the 'message' object directly
    attack_tree_code = response.content[0].text

    # Remove Markdown code block delimiters using regular expression
    attack_tree_code = re.sub(r'^```mermaid\s*|\s*```$', '', attack_tree_code, flags=re.MULTILINE)

    return attack_tree_code