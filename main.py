# This code is a Streamlit web application that uses OpenAI's GPT-3 model to generate a threat model for a given application based on the STRIDE methodology. The user provides the application description and other details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. After submitting, the GPT-3 model generates a threat model based on the provided details.

# The app layout includes input fields for the application details, a submit button, and a sidebar with helpful information, such as how to use the app, an example application description, and FAQs. The app also includes a "Copy to Clipboard" button for copying the generated threat model.


import streamlit as st
from langchain import PromptTemplate
from langchain.llms import OpenAI

import os

# Define the GPT-3 prompt template
template = """
    Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce a list of specific threats for the application. Your analysis should provide a credible scenario in which each threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

    
    In addition to the description, you will be provided with the following key details about the application that you will need to consider when producing your threat model:
    - The type of application
    - The methods used to authenticate users to the application
    - Whether or not the application is internet-facing
    - Whether or not the application processes sensitive data
    - Whether or not the application uses privileged access management to protect privileged accounts

    Below is the application description and key details:
    APPLICATION TYPE: {app_type}
    AUTHENTICATION METHODS: {authentication}
    INTERNET FACING: {internet_facing}
    SENSITIVE DATA: {sensitive_data}
    PRIVILEGED ACCESS MANAGEMENT: {pam}
    APPLICATION DESCRIPTION: {app_input}

    Your output should be in the form of a markdown table with the following columns:
    - Column A: Threat Type
    - Column B: Scenario
    - Column C: Potential Impact
    
    Below the table you should add a new section and then make some suggestions to the user on how they can improve the application description could to enable you to produce a more comprehensive threat model.

    YOUR RESPONSE:
"""

# Create a PromptTemplate object with the specified input variables
prompt = PromptTemplate(
    input_variables=["app_type", "authentication", "internet_facing", "sensitive_data", "pam", "app_input"],
    template=template,
)

# Function to load LLM (Language Model) with given API key
def load_LLM(api_key):
    os.environ['OPENAI_API_KEY'] = api_key
    llm = OpenAI(temperature=0.7, model_name="text-davinci-003", max_tokens=1000)
    return llm

# Set Streamlit page configurations
st.set_page_config(page_title="STRIDE GPT", page_icon=":shield:", layout="wide", initial_sidebar_state="expanded")
st.header("STRIDE GPT🛡️")

st.markdown("""
    **S**poofing 🕶 **T**ampering 🛠️ **R**epudiation 🤷 **I**nformation Disclosure 📢 **D**enial of Service 🛑 **E**levation of Privilege 🤴
    """)

# Function to get user input for the application description
def get_input():
    input_text = st.text_area(label="Describe the application to be modelled", placeholder="Enter your application details...", height=150, key="app_input", help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.")
    return input_text
    

# Get application description from the user
app_input = get_input()

# Create two columns layout for input fields
col1, col2 = st.columns(2)

# Create input fields for app_type, sensitive_data and pam
with col1:
    app_type = st.selectbox(
        label="Select the application type", 
        options=["Web application", "Mobile application", "Desktop application", "Cloud application", "IoT application", "Other"], 
        key="app_type"
        )

    sensitive_data = st.selectbox(
        label="What is the highest sensitivity level of the data processed by the application?",
        options=["Top Secret", "Secret", "Confidential", "Restricted", "Unclassified", "None"],
        key="sensitive_data"
        )
    
    pam = st.selectbox(
        label="Are privileged accounts stored in a Privileged Access Management (PAM) solution?",
        options=["Yes", "No"],
        key="pam"
    )

# Create input fields for internet_facing and authentication
with col2:
    internet_facing = st.selectbox(
        label="Is the application internet-facing?", 
        options=["Yes", "No"], 
        key="internet_facing"
        )
    
    authentication = st.multiselect(
        'What authentication methods are supported by the application?',
        ['SSO', 'MFA', 'OAUTH2', 'Basic', 'None'],
        key="authentication"
    )

# Add instructions on how to use the app to the sidebar
st.sidebar.header("How to use STRIDE GPT")

with st.sidebar:
    st.markdown("""
    1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) below 🔑
    2. Provide details of the application that you would like to threat model  📝
    3. Click **Submit** to generate a threat list 🚀
    """)

    # Add OpenAI API key input field to the sidebar
    openai_api_key = st.text_input("Enter your OpenAI API key:", type="password", help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).")
    st.markdown("""---""")

# Add "About" section to the sidebar
st.sidebar.header("About")

with st.sidebar:
    st.markdown("Welcome to STRIDE GPT, an AI-powered tool designed to help teams produce better threat models for their applications.")
    st.markdown("Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. STRIDE GPT aims to help teams produce more comprehensive threat models by leveraging the power of GPT-3 to generate a list of specific threats for an application based on the details provided.")
    st.markdown("Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/).")
    st.markdown("""---""")


# Add "Example Application Description" section to the sidebar
st.sidebar.header("Example Application Description")

with st.sidebar:
    st.markdown("Below is an example application description that you can use to test STRIDE GPT:")
    st.markdown("> A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users.")
    st.markdown("""---""")

# Add "FAQs" section to the sidebar
st.sidebar.header("FAQs")

with st.sidebar:
    st.markdown("""
    ### **What is STRIDE?**
    STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.
    """)
    st.markdown("""
    ### **How does STRIDE GPT work?**
    When you enter an application description and other relevant details, the tool will use a GPT-3 model to generate a threat model for your application. The model uses the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.
    """)
    st.markdown("""
    ### **Do you store the application details provided?**
    No, STRIDE GPT does not store your application description or other details. All entered data is deleted after you close the browser tab.
    """)
    st.markdown("""
    ### **Why does it take so long to generate a threat model?**
    If you are using a free OpenAI API key, it will take a while to generate a threat model. This is because the free API key has strict rate limits. To speed up the process, you can use a paid API key.
    """)
    st.markdown("""
    ### **Are the threat models 100% accurate?**
    No, the threat models are not 100% accurate. STRIDE GPT uses GPT-3 to generate threat models. GPT-3 is a powerful language model, but it sometimes makes mistakes is prone to 'hallucinations' (generating irrelevant or inaccurate content). Please use the output only as a starting point for identifying and addressing potential security risks in your applications.
    """)
    st.markdown("""
    ### **How can I improve the accuracy of the threat models?**
    You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.
    """)

# Create a submit button
submit_button = st.button(label="Submit")

# Display the threat model output header
st.markdown("### Threat Model Output")

# If the submit button is clicked and the user has provided an application description
if submit_button and app_input:
    # Load the Language Model with the provided API key
    llm = load_LLM(openai_api_key)

    # Format the prompt with the user-provided details
    prompt_with_details = prompt.format(app_type=app_type, authentication=authentication, internet_facing=internet_facing, sensitive_data=sensitive_data, pam=pam, app_input=app_input)

    # Show a spinner while generating the threat model
    with st.spinner("Analysing potential threats..."):
        model_output = llm(prompt_with_details)

    # Display the generated threat model
    st.write(model_output)

    # Add a button to allow the user to download the output as a Markdown file
    st.download_button(
    label="Download Output",
    data=model_output,
    file_name="stride_gpt_output.md",
    mime="text/markdown",
    )

# If the submit button is clicked and the user has not provided an application description
if submit_button and not app_input:
    st.error("Please enter your application details before submitting.")
    