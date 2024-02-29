import json
import re
import streamlit as st
import streamlit.components.v1 as components
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
from openai import OpenAI
from openai import AzureOpenAI


# ------------------ Helper Functions ------------------ #

# Function to get user input for the application description and key details
def get_input():
    input_text = st.text_area(
        label="Describe the application to be modelled",
        placeholder="Enter your application details...",
        height=150,
        key="app_input",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )
    return input_text


# Function to create a prompt for generating a threat model
def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, pam, app_input):
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description and additional provided to you to produce a list of specific threats for the application.

For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.


When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact". 

Under "improvement_suggestions", include an array of strings with suggestions on how the threat modeller can improve their application description in order to allow the tool to produce a more comprehensive threat model.

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
PRIVILEGED ACCESS MANAGEMENT: {pam}
APPLICATION DESCRIPTION: {app_input}

Example of expected JSON response format:
  
    {{
      "threat_model": [
        {{
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 1",
          "Potential Impact": "Example Potential Impact 1"
        }},
        {{
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 2",
          "Potential Impact": "Example Potential Impact 2"
        }},
        // ... more threats
      ],
      "improvement_suggestions": [
        "Example improvement suggestion 1.",
        "Example improvement suggestion 2.",
        // ... more suggestions
      ]
    }}
"""
    return prompt


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content

# Function to get threat model from the Azure OpenAI response.
def get_threat_model_azure(api_key, model_name, prompt):
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
    response_content = json.loads(response.choices[0].message.content)

    return response_content

# Function to get threat model from the Azure OpenAI response.
def get_threat_model_mistral(api_key, model_name, prompt):
    client = MistralClient(api_key=mistral_api_key)

    response = client.chat(
        model = mistral_model,
        response_format={"type": "json_object"},
        messages=[
            ChatMessage(role="user", content=prompt)
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content


# Function to convert JSON to Markdown for display.    
def json_to_markdown(threat_model, improvement_suggestions):
    markdown_output = "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
    
    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"
    
    return markdown_output


# Function to create a prompt to generate an attack tree
def create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, pam, app_input):
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
PRIVILEGED ACCESS MANAGEMENT: {pam}
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
def get_attack_tree_azure(api_key, model_name, prompt):
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
def get_attack_tree_mistral(api_key, model_name, prompt):
    client = MistralClient(api_key=mistral_api_key)

    response = client.chat(
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

# Function to render Mermaid diagram
def mermaid(code: str, height: int = 500) -> None:
    components.html(
        f"""
        <pre class="mermaid" style="height: {height}px;">
            {code}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        height=height,
    )


# Function to create a prompt to generate mitigating controls
def create_mitigations_prompt(threats):
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology. Your task is to provide potential mitigations for the threats identified in the threat model. It is very important that your responses are tailored to reflect the details of the threats.

Your output should be in the form of a markdown table with the following columns:
    - Column A: Threat Type
    - Column B: Scenario
    - Column C: Suggested Mitigation(s)

Below is the list of identified threats:
{threats}

YOUR RESPONSE (do not wrap in a code block):
"""
    return prompt


# Function to get mitigations from the GPT response.
def get_mitigations(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model = model_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations


# Function to get mitigations from the Azure OpenAI response.
def get_mitigations_azure(api_key, model_name, prompt):
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


# Function to get mitigations from the Mistral model's response.
def get_mitigations_mistral(api_key, model_name, prompt):
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


# ------------------ Streamlit UI Configuration ------------------ #

st.set_page_config(
    page_title="STRIDE GPT",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Create three columns
col1, col2, col3 = st.columns([1,2,1])

# Use the middle column to display the logo, which will be centered
with col2:
    st.image("logo.png", width=450)



# ------------------ Main App UI ------------------ #

# Get application description from the user
app_input = get_input()

# Create two columns layout for input fields
col1, col2 = st.columns(2)

# Create input fields for app_type, sensitive_data and pam
with col1:
    app_type = st.selectbox(
        label="Select the application type",
        options=[
            "Web application",
            "Mobile application",
            "Desktop application",
            "Cloud application",
            "IoT application",
            "Other",
        ],
        key="app_type",
    )

    sensitive_data = st.selectbox(
        label="What is the highest sensitivity level of the data processed by the application?",
        options=[
            "Top Secret",
            "Secret",
            "Confidential",
            "Restricted",
            "Unclassified",
            "None",
        ],
        key="sensitive_data",
    )

    pam = st.selectbox(
        label="Are privileged accounts stored in a Privileged Access Management (PAM) solution?",
        options=["Yes", "No"],
        key="pam",
    )

# Create input fields for internet_facing and authentication
with col2:
    internet_facing = st.selectbox(
        label="Is the application internet-facing?",
        options=["Yes", "No"],
        key="internet_facing",
    )

    authentication = st.multiselect(
        "What authentication methods are supported by the application?",
        ["SSO", "MFA", "OAUTH2", "Basic", "None"],
        key="authentication",
    )



# ------------------ Sidebar ------------------ #

# Add instructions on how to use the app to the sidebar
st.sidebar.header("How to use STRIDE GPT")

with st.sidebar:
    # Add model selection input field to the sidebar
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["OpenAI API", "Azure OpenAI Service", "Mistral API"],
        key="model_provider",
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    if model_provider == "OpenAI API":
        st.markdown(
        """
    1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add OpenAI API key input field to the sidebar
        openai_api_key = st.text_input(
            "Enter your OpenAI API key:",
            type="password",
            help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
        )

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-4-turbo-preview", "gpt-4", "gpt-3.5-turbo"],
            key="selected_model",
            help="OpenAI have moved to continuous model upgrades so `gpt-3.5-turbo`, `gpt-4` and `gpt-4-turbo-preview` point to the latest available version of each model.",
        )

    if model_provider == "Azure OpenAI Service":
        st.markdown(
        """
    1. Enter your Azure OpenAI API key, endpoint and deployment name below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )

        # Add Azure OpenAI API key input field to the sidebar
        azure_api_key = st.text_input(
            "Azure OpenAI API key:",
            type="password",
            help="You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
        )
        
        # Add Azure OpenAI endpoint input field to the sidebar
        azure_api_endpoint = st.text_input(
            "Azure OpenAI endpoint:",
            help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
        )

        # Add Azure OpenAI deployment name input field to the sidebar
        azure_deployment_name = st.text_input(
            "Deployment name:",
        )
        
        st.info("Please note that you must use an 1106-preview model deployment.")

        azure_api_version = '2023-12-01-preview' # Update this as needed

        st.write(f"Azure API Version: {azure_api_version}")

    if model_provider == "Mistral API":
        st.markdown(
        """
    1. Enter your [Mistral API key](https://console.mistral.ai/api-keys/) and chosen model below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
    """
    )
        # Add OpenAI API key input field to the sidebar
        mistral_api_key = st.text_input(
            "Enter your Mistral API key:",
            type="password",
            help="You can generate a Mistral API key in the [Mistral console](https://console.mistral.ai/api-keys/).",
        )

        # Add model selection input field to the sidebar
        mistral_model = st.selectbox(
            "Select the model you would like to use:",
            ["mistral-large-latest", "mistral-small-latest"],
            key="selected_model",
        )

    st.markdown("""---""")

# Add "About" section to the sidebar
st.sidebar.header("About")

with st.sidebar:
    st.markdown(
        "Welcome to STRIDE GPT, an AI-powered tool designed to help teams produce better threat models for their applications."
    )
    st.markdown(
        "Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. STRIDE GPT aims to help teams produce more comprehensive threat models by leveraging the power of Large Language Models (LLMs) to generate a threat list, attack tree and/or mitigating controls for an application based on the details provided."
    )
    st.markdown("Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/).")
    # Add "Star on GitHub" link to the sidebar
    st.sidebar.markdown(
        "⭐ Star on GitHub: [![Star on GitHub](https://img.shields.io/github/stars/mrwadams/stride-gpt?style=social)](https://github.com/mrwadams/stride-gpt)"
    )
    st.markdown("""---""")


# Add "Example Application Description" section to the sidebar
st.sidebar.header("Example Application Description")

with st.sidebar:
    st.markdown(
        "Below is an example application description that you can use to test STRIDE GPT:"
    )
    st.markdown(
        "> A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users."
    )
    st.markdown("""---""")

# Add "FAQs" section to the sidebar
st.sidebar.header("FAQs")

with st.sidebar:
    st.markdown(
        """
    ### **What is STRIDE?**
    STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.
    """
    )
    st.markdown(
        """
    ### **How does STRIDE GPT work?**
    When you enter an application description and other relevant details, the tool will use a GPT model to generate a threat model for your application. The model uses the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.
    """
    )
    st.markdown(
        """
    ### **Do you store the application details provided?**
    No, STRIDE GPT does not store your application description or other details. All entered data is deleted after you close the browser tab.
    """
    )
    st.markdown(
        """
    ### **Why does it take so long to generate a threat model?**
    If you are using a free OpenAI API key, it will take a while to generate a threat model. This is because the free API key has strict rate limits. To speed up the process, you can use a paid API key.
    """
    )
    st.markdown(
        """
    ### **Are the threat models 100% accurate?**
    No, the threat models are not 100% accurate. STRIDE GPT uses GPT Large Language Models (LLMs) to generate its output. The GPT models are powerful, but they sometimes makes mistakes and are prone to 'hallucinations' (generating irrelevant or inaccurate content). Please use the output only as a starting point for identifying and addressing potential security risks in your applications.
    """
    )
    st.markdown(
        """
    ### **How can I improve the accuracy of the threat models?**
    You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.
    """
    )

st.markdown("""---""")



# ------------------ Threat Model Generation ------------------ #

# Create a collapsible section for Threat Modelling
with st.expander("Threat Model", expanded=False):
    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label="Generate Threat Model")

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and app_input:
        # Generate the prompt using the create_prompt function
        threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, pam, app_input)

        # Show a spinner while generating the threat model
        with st.spinner("Analysing potential threats..."):
            try:
                # Call one of the get_threat_model functions with the generated prompt
                if model_provider == "Azure OpenAI Service":
                    model_output = get_threat_model_azure(azure_api_key, azure_deployment_name, threat_model_prompt)
                elif model_provider == "OpenAI API":
                    model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                elif model_provider == "Mistral API":
                    model_output = get_threat_model_mistral(mistral_api_key, mistral_model, threat_model_prompt)
                        
                # Access the threat model and improvement suggestions from the parsed content
                threat_model = model_output.get("threat_model", [])
                improvement_suggestions = model_output.get("improvement_suggestions", [])

                # Save the threat model to the session state for later use in mitigations
                st.session_state['threat_model'] = threat_model

                # Convert the threat model JSON to Markdown
                markdown_output = json_to_markdown(threat_model, improvement_suggestions)

                # Display the threat model in Markdown
                st.markdown(markdown_output)

            except Exception as e:
                st.error(f"Error generating threat model: {e}")

            # Add a button to allow the user to download the output as a Markdown file
            st.download_button(
                label="Download Threat Model",
                data=markdown_output,  # Use the Markdown output
                file_name="stride_gpt_threat_model.md",
                mime="text/markdown",
            )

    # If the submit button is clicked and the user has not provided an application description
    if threat_model_submit_button and not app_input:
        st.error("Please enter your application details before submitting.")



# ------------------ Attack Tree Generation ------------------ #

# Create a collapsible section for Attack Tree
with st.expander("Attack Tree", expanded=False):
    if model_provider == "Mistral API" and mistral_model == "mistral-small-latest":
        st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
    # Create a submit button for Attack Tree
    attack_tree_submit_button = st.button(label="Generate Attack Tree")

    # If the Generate Attack Tree button is clicked and the user has provided an application description
    if attack_tree_submit_button and app_input:
        # Generate the prompt using the create_attack_tree_prompt function
        attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, pam, app_input)

        # Show a spinner while generating the attack tree
        with st.spinner("Generating attack tree..."):
            try:
                # Call to either of the get_attack_tree functions with the generated prompt
                if model_provider == "Azure OpenAI Service":
                    mermaid_code = get_attack_tree_azure(azure_api_key, azure_deployment_name, attack_tree_prompt)
                elif model_provider == "OpenAI API":
                    mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)
                elif model_provider == "Mistral API":
                    mermaid_code = get_attack_tree_mistral(mistral_api_key, mistral_model, attack_tree_prompt)

                # Display the generated attack tree code
                st.write("Attack Tree Code:")
                st.code(mermaid_code)

                # Visualise the attack tree using the Mermaid custom component
                st.write("Attack Tree Diagram Preview:")
                mermaid(mermaid_code)
                
                col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                
                with col1:              
                    # Add a button to allow the user to download the Mermaid code
                    st.download_button(
                        label="Download Diagram Code",
                        data=mermaid_code,
                        file_name="attack_tree.md",
                        mime="text/plain",
                        help="Download the Mermaid code for the attack tree diagram."
                    )

                with col2:
                    # Add a button to allow the user to open the Mermaid Live editor
                    mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                
                with col3:
                    # Blank placeholder
                    st.write("")
                
                with col4:
                    # Blank placeholder
                    st.write("")
                
                with col5:
                    # Blank placeholder
                    st.write("")

            except Exception as e:
                st.error(f"Error generating attack tree: {e}")



# ------------------ Mitigations Generation ------------------ #

# Create a collapsible section for Mitigations
with st.expander("Mitigations", expanded=False):
    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label="Suggest Mitigations")

    # If the Suggest Mitigations button is clicked and the user has identified threats
    if mitigations_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            # Generate the prompt using the create_mitigations_prompt function
            mitigations_prompt = create_mitigations_prompt(threats_markdown)

            # Show a spinner while suggesting mitigations
            with st.spinner("Suggesting mitigations..."):
                try:
                    # Call to either of the get_mitigations functions with the generated prompt
                    if model_provider == "Azure OpenAI Service":
                        mitigations_markdown = get_mitigations_azure(azure_api_key, azure_deployment_name, mitigations_prompt)
                    elif model_provider == "OpenAI API":
                        mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)
                    elif model_provider == "Mistral API":
                        mitigations_markdown = get_mitigations_mistral(mistral_api_key, mistral_model, mitigations_prompt)

                    # Display the suggested mitigations in Markdown
                    st.markdown(mitigations_markdown)

                    # Add a button to allow the user to download the mitigations as a Markdown file
                    st.download_button(
                        label="Download Mitigations",
                        data=mitigations_markdown,
                        file_name="mitigations.md",
                        mime="text/markdown",
                    )
                except Exception as e:
                    st.error(f"Error suggesting mitigations: {e}")
        else:
            st.error("Please generate a threat model first before suggesting mitigations.")