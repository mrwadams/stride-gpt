# config.py

ABOUT_SECTION = """
# About

Welcome to STRIDE GPT, an AI-powered tool designed to help teams produce better threat models for their applications.

Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. STRIDE GPT aims to help teams produce more comprehensive threat models by leveraging the power of Large Language Models (LLMs) to generate a threat list, attack tree and/or mitigating controls for an application based on the details provided.

Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/).

⭐ Star on GitHub: [![Star on GitHub](https://img.shields.io/github/stars/mrwadams/stride-gpt?style=social)](https://github.com/mrwadams/stride-gpt)
"""

EXAMPLE_APPLICATION_SECTION = """
# Example Application Description

Below is an example application description that you can use to test STRIDE GPT:

> A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users.
"""

FAQ_SECTION = """
# FAQs

### **What is STRIDE?**
STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.

### **How does STRIDE GPT work?**
When you enter an application description and other relevant details, the tool will use a GPT model to generate a threat model for your application. The model uses the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.

### **Do you store the application details provided?**
No, STRIDE GPT does not store your application description or other details. All entered data is deleted after you close the browser tab.

### **Why does it take so long to generate a threat model?**
If you are using a free OpenAI API key, it will take a while to generate a threat model. This is because the free API key has strict rate limits. To speed up the process, you can use a paid API key.

### **Are the threat models 100% accurate?**
No, the threat models are not 100% accurate. STRIDE GPT uses GPT Large Language Models (LLMs) to generate its output. The GPT models are powerful, but they sometimes make mistakes and are prone to 'hallucinations' (generating irrelevant or inaccurate content). Please use the output only as a starting point for identifying and addressing potential security risks in your applications.

### **How can I improve the accuracy of the threat models?**
You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.
"""

THREAT_MODEL_SECTION = """
A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
"""

COMBINED_MARKDOWN = f"{ABOUT_SECTION}\n---\n{EXAMPLE_APPLICATION_SECTION}\n---\n{FAQ_SECTION}"

PROVIDERS = {
    'azure': "Azure OpenAI Service",
    'openai': "OpenAI API",
    'google': "Google AI API",
    'mistral': "Mistral API",
    'ollama': "Ollama"
}

APPLICATION_TYPES = [
    "Web application", "Mobile application", "Desktop application", "Cloud application", "IoT application", "Other"
]
CLASSIFICATION_LEVELS = [
    "Top Secret", "Secret", "Confidential", "Restricted", "Unclassified", "None"
]
AUTHENTICATION_METHODS = ["SSO", "MFA", "OAUTH2", "Basic", "None"]
INTERNET_FACING = ['Yes', 'No']

ARG_HELPERS = {
    "provider": "Select the provider. This will determine the models available for selection.",
    "model": "Select the model you would like to use.",
    "key": "Provide the provider API key.",
    "application-type": "Select the application type.",
    "sensitive-data": "What is the highest sensitivity level of the data processed by the application?",
    "internet-facing": "Is the application internet-facing?",
    "authentication": "What authentication methods are supported by the application?",
    "application_input": "Describe the application to be modeled.",
    "output-file": "If provided, save the output content to this file.",
    "output-format": "Choose the output format. 'markdown' or 'json'. Default is 'markdown'."
}