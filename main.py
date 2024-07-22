import base64
import streamlit as st
import streamlit.components.v1 as components
from streamlit_option_menu import option_menu

from query_data import query_rag
from db_ops import add_data

# Imports for prompts files i.e., stride.py, dread.py, etc.
from stride import create_threat_model_prompt as create_stride_threat_model_prompt
from dread import create_dread_assessment_prompt
from pasta import create_pasta_prompt
from owasp import create_owasp_prompt

# Import other modules here
from threat_model import (
    get_threat_model,
    get_threat_model_azure,
    get_threat_model_google,
    json_to_markdown,
    get_image_analysis,
    create_image_analysis_prompt,
)
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google
from dread import get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, dread_json_to_markdown
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google



# UI operations class
class UIOps:
    def __init__(self):
        self.chroma_db = None

    def handle_text_submission(self, text, chat_history):
        user_input = text
        chat_history += f"User: {user_input}\n"
        print("chat_history: ", chat_history)
        print("END OF CHAT HISTORY ------------------------------------------------------")
        
        result = query_rag(user_input, chat_history, fetch_context=True, chroma_db=self.chroma_db, route=None)
        result = result.content
        chat_history += f"Bot: {result}\n"
        
        return result, chat_history

ui_ops = UIOps()

# Define mermaid function to render Mermaid diagrams
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

# Function to create the sidebar
def create_sidebar():
    with st.sidebar:
        st.title("Adversarial Systems")
        st.caption("AI Powered Cybersecurity")
        st.image("logo.png", width=240)  # Replace with your logo

        selected = option_menu(
            menu_title=None,
            options=[
                "Dashboard", "Copilot", "Pen Test", "Threat Model",
                "RFPs", "Integrations", "Team", "Tutorials", "Settings", "About"
            ],
            icons=[
                "speedometer2", "chat-dots", "person", "file-earmark-text",
                "search", "globe", "people", "book", "gear", "info-circle"
            ],
            default_index=0,
            styles={
                "container": {"padding": "0!important", "background-color": "transparent"},
                "icon": {"color": "#000000", "font-size": "14px"},
                "nav-link": {
                    "font-size": "14px",
                    "color": "#000000",
                    "text-align": "left",
                    "margin": "0px",
                    "--hover-color": "rgba(211, 211, 211, 0.5)",
                },
                "nav-link-selected": {"background-color": "rgba(255, 255, 255, 0.2)"},
            },
        )

        st.title("Beta")
        st.caption("V1.0")

    return selected

# Function to get user input for the application description and key details
def get_input():
    input_text = st.text_area(
        label="Describe the application to be modelled",
        placeholder="Enter your application details...",
        height=150,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )
    st.session_state['app_input'] = input_text
    return input_text

# Main function
def main():
    selected = create_sidebar()

    if selected == "RFPs":
        st.title("RFPs Page")

        col1, col2, col3 = st.columns([1, 2, 1])

        with col1:
            st.subheader("Chats")
            st.button("+ New Chat")
            st.text("(Chat list would appear here)")

        with col2:
            st.text_input("Send a message...")

        with col3:
            st.subheader("Local Docs")
            st.button("+ Add Docs")
            st.text("Select a collection to make it available to the chat model")

    elif selected == "Threat Model":
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["Threat Model", "Attack Tree", "Mitigations", "DREAD", "Test Cases"])

        with tab1:
            st.header("Threat Model")
            st.markdown("""
            A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
            understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
            """)
            st.markdown("""---""")

            threat_model = st.selectbox(
                "Select your preferred threat model:",
                ["STRIDE", "DREAD", "PASTA", "OWASP"],
                key="threat_model_provider_tab",
                help="Select the threat model you would like to use.",
            )

            model_provider = st.selectbox(
                "Select your preferred model provider:",
                ["OpenAI API", "Azure OpenAI Service", "Google AI API"],
                key="model_provider_tab",
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
                openai_api_key = st.text_input(
                    "Enter your OpenAI API key:",
                    type="password",
                    help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
                    key="openai_api_key_tab"
                )
                selected_model = st.selectbox(
                    "Select the model you would like to use:",
                    ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                    key="selected_model_tab",
                    help="OpenAI have moved to continuous model upgrades so `gpt-3.5-turbo`, `gpt-4` and `gpt-4-turbo` point to the latest available version of each model.",
                )

            if model_provider == "Azure OpenAI Service":
                st.markdown(
                    """
                    1. Enter your Azure OpenAI API key, endpoint and deployment name below 🔑
                    2. Provide details of the application that you would like to threat model  📝
                    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
                    """
                )
                azure_api_key = st.text_input(
                    "Azure OpenAI API key:",
                    type="password",
                    help="You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
                    key="azure_api_key_tab"
                )
                azure_api_endpoint = st.text_input(
                    "Azure OpenAI endpoint:",
                    help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
                    key="azure_api_endpoint_tab"
                )
                azure_deployment_name = st.text_input(
                    "Deployment name:",
                    key="azure_deployment_name_tab"
                )
                st.info("Please note that you must use an 1106-preview model deployment.")
                azure_api_version = '2023-12-01-preview'  # Update this as needed
                st.write(f"Azure API Version: {azure_api_version}")

            if model_provider == "Google AI API":
                st.markdown(
                    """
                    1. Enter your [Google AI API key](https://makersuite.google.com/app/apikey) and chosen model below 🔑
                    2. Provide details of the application that you would like to threat model  📝
                    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
                    """
                )
                google_api_key = st.text_input(
                    "Enter your Google AI API key:",
                    type="password",
                    help="You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
                    key="google_api_key_tab"
                )
                google_model = st.selectbox(
                    "Select the model you would like to use:",
                    ["gemini-1.5-pro-latest"],
                    key="google_model_tab",
                )

            col1, col2 = st.columns([1, 1])

            if 'app_input' not in st.session_state:
                st.session_state['app_input'] = ''

            with col1:
                if model_provider == "OpenAI API" and selected_model in ["gpt-4-turbo", "gpt-4o"]:
                    uploaded_file = st.file_uploader("Upload architecture diagram", type=["jpg", "jpeg", "png"])

                    if uploaded_file is not None:
                        if not openai_api_key:
                            st.error("Please enter your OpenAI API key to analyse the image.")
                        else:
                            if 'uploaded_file' not in st.session_state or st.session_state.uploaded_file != uploaded_file:
                                st.session_state.uploaded_file = uploaded_file
                                with st.spinner("Analysing the uploaded image..."):
                                    def encode_image(uploaded_file):
                                        return base64.b64encode(uploaded_file.read()).decode('utf-8')

                                    base64_image = encode_image(uploaded_file)

                                    image_analysis_prompt = create_image_analysis_prompt()

                                    try:
                                        image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
                                        if image_analysis_output and 'choices' in image_analysis_output and image_analysis_output['choices'][0]['message']['content']:
                                            image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                                            st.session_state.image_analysis_content = image_analysis_content
                                            st.session_state['app_input'] = image_analysis_content
                                        else:
                                            st.error("Failed to analyze the image. Please check the API key and try again.")
                                    except KeyError as e:
                                        st.error("Failed to analyze the image. Please check the API key and try again.")
                                        print(f"Error: {e}")
                                    except Exception as e:
                                        st.error("An unexpected error occurred while analyzing the image.")
                                        print(f"Error: {e}")

                    app_input = st.text_area(
                        label="Describe the application to be modelled",
                        value=st.session_state['app_input'],
                        key="app_input_widget",
                        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
                    )
                    if app_input != st.session_state['app_input']:
                        st.session_state['app_input'] = app_input

                else:
                    app_input = get_input()
                    st.session_state['app_input'] = app_input

            app_input = st.session_state['app_input']

            with col2:
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

            threat_model_submit_button = st.button(label="Generate Threat Model")

            if threat_model_submit_button and st.session_state.get('app_input'):
                app_input = st.session_state['app_input']
                if threat_model == "STRIDE":
                    threat_model_prompt = create_stride_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)
                elif threat_model == "DREAD":
                    threat_model_prompt = create_dread_assessment_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)
                elif threat_model == "PASTA":
                    threat_model_prompt = create_pasta_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)
                elif threat_model == "OWASP":
                    threat_model_prompt = create_owasp_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

                with st.spinner("Analysing potential threats..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            if model_provider == "Azure OpenAI Service":
                                model_output = get_threat_model_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, threat_model_prompt)
                            elif model_provider == "OpenAI API":
                                model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                            elif model_provider == "Google AI API":
                                model_output = get_threat_model_google(google_api_key, google_model, threat_model_prompt)

                            threat_model = model_output.get("threat_model", [])
                            improvement_suggestions = model_output.get("improvement_suggestions", [])

                            st.session_state['threat_model'] = threat_model
                            break
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                st.error(f"Error generating threat model after {max_retries} attempts: {e}")
                                threat_model = []
                                improvement_suggestions = []
                            else:
                                st.warning(f"Error generating threat model. Retrying attempt {retry_count+1}/{max_retries}...")

                markdown_output = json_to_markdown(threat_model, improvement_suggestions)
                st.markdown(markdown_output)

                st.download_button(
                    label="Download Threat Model",
                    data=markdown_output,
                    file_name="stride_gpt_threat_model.md",
                    mime="text/markdown",
                )

            if threat_model_submit_button and not st.session_state.get('app_input'):
                st.error("Please enter your application details before submitting.")

        with tab2:
            st.markdown("""
    Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
    with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system 
    vulnerabilities and prioritising mitigation efforts.
    """)
            st.markdown("""---""")
            if model_provider == "Google AI API":
                st.warning("⚠️ Google's safety filters prevent the reliable generation of attack trees. Please use a different model provider.")
            else:
                attack_tree_submit_button = st.button(label="Generate Attack Tree")
                
                if attack_tree_submit_button and st.session_state.get('app_input'):
                    app_input = st.session_state.get('app_input')
                    attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

                    with st.spinner("Generating attack tree..."):
                        try:
                            if model_provider == "Azure OpenAI Service":
                                mermaid_code = get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, attack_tree_prompt)
                            elif model_provider == "OpenAI API":
                                mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)

                            st.write("Attack Tree Code:")
                            st.code(mermaid_code)

                            st.write("Attack Tree Diagram Preview:")
                            mermaid(mermaid_code)
                            
                            col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                            
                            with col1:              
                                st.download_button(
                                    label="Download Diagram Code",
                                    data=mermaid_code,
                                    file_name="attack_tree.md",
                                    mime="text/plain",
                                    help="Download the Mermaid code for the attack tree diagram."
                                )

                            with col2:
                                st.link_button("Open Mermaid Live", "https://mermaid.live")
                            
                            with col3:
                                st.write("")
                            
                            with col4:
                                st.write("")
                            
                            with col5:
                                st.write("")

                        except Exception as e:
                            st.error(f"Error generating attack tree: {e}")

        with tab3:
            st.markdown("""
    Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
    countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
    the security posture of the application and protect against potential attacks.
    """)
            st.markdown("""---""")
            
            mitigations_submit_button = st.button(label="Suggest Mitigations")

            if mitigations_submit_button:
                if 'threat_model' in st.session_state and st.session_state['threat_model']:
                    threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                    mitigations_prompt = create_mitigations_prompt(threats_markdown)

                    with st.spinner("Suggesting mitigations..."):
                        max_retries = 3
                        retry_count = 0
                        while retry_count < max_retries:
                            try:
                                if model_provider == "Azure OpenAI Service":
                                    mitigations_markdown = get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, mitigations_prompt)
                                elif model_provider == "OpenAI API":
                                    mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)
                                elif model_provider == "Google AI API":
                                    mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt)

                                st.markdown(mitigations_markdown)
                                break
                            except Exception as e:
                                retry_count += 1
                                if retry_count == max_retries:
                                    st.error(f"Error suggesting mitigations after {max_retries} attempts: {e}")
                                    mitigations_markdown = ""
                                else:
                                    st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count+1}/{max_retries}...")
                    
                    st.markdown("")

                    st.download_button(
                        label="Download Mitigations",
                        data=mitigations_markdown,
                        file_name="mitigations.md",
                        mime="text/markdown",
                    )
                else:
                    st.error("Please generate a threat model first before suggesting mitigations.")

        with tab4:
            st.markdown("""
    DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
    **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
    focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
    """)
            st.markdown("""---""")
            
            dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
            if dread_assessment_submit_button:
                if 'threat_model' in st.session_state and st.session_state['threat_model']:
                    threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                    dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown)
                    with st.spinner("Generating DREAD Risk Assessment..."):
                        max_retries = 3
                        retry_count = 0
                        while retry_count < max_retries:
                            try:
                                if model_provider == "Azure OpenAI Service":
                                    dread_assessment = get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, dread_assessment_prompt)
                                elif model_provider == "OpenAI API":
                                    dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt)
                                elif model_provider == "Google AI API":
                                    dread_assessment = get_dread_assessment_google(google_api_key, google_model, dread_assessment_prompt)

                                st.session_state['dread_assessment'] = dread_assessment
                                break
                            except Exception as e:
                                retry_count += 1
                                if retry_count == max_retries:
                                    st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                                    dread_assessment = []
                                else:
                                    st.warning(f"Error generating DREAD risk assessment. Retrying attempt {retry_count+1}/{max_retries}...")
                    dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
                    st.markdown(dread_assessment_markdown)
                    st.download_button(
                        label="Download DREAD Risk Assessment",
                        data=dread_assessment_markdown,
                        file_name="dread_assessment.md",
                        mime="text/markdown",
                    )
                else:
                    st.error("Please generate a threat model first before requesting a DREAD risk assessment.")

        with tab5:
            st.markdown("""
    Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
    addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application 
    behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test 
    scenarios.
    """)
            st.markdown("""---""")
                    
            test_cases_submit_button = st.button(label="Generate Test Cases")

            if test_cases_submit_button:
                if 'threat_model' in st.session_state and st.session_state['threat_model']:
                    threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
                    test_cases_prompt = create_test_cases_prompt(threats_markdown)

                    with st.spinner("Generating test cases..."):
                        max_retries = 3
                        retry_count = 0
                        while retry_count < max_retries:
                            try:
                                if model_provider == "Azure OpenAI Service":
                                    test_cases_markdown = get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, test_cases_prompt)
                                elif model_provider == "OpenAI API":
                                    test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)
                                elif model_provider == "Google AI API":
                                    test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt)

                                st.markdown(test_cases_markdown)
                                break
                            except Exception as e:
                                retry_count += 1
                                if retry_count == max_retries:
                                    st.error(f"Error generating test cases after {max_retries} attempts: {e}")
                                    test_cases_markdown = ""
                                else:
                                    st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{max_retries}...")
                    
                    st.markdown("")

                    st.download_button(
                        label="Download Test Cases",
                        data=test_cases_markdown,
                        file_name="test_cases.md",
                        mime="text/markdown",
                    )
                else:
                    st.error("Please generate a threat model first before requesting test cases.")

    elif selected == "Settings":
        st.header("Settings")
        st.markdown("Configure your settings here.")
        
        model_provider = st.selectbox(
            "Select your preferred model provider:",
            ["OpenAI API", "Azure OpenAI Service", "Google AI API"],
            key="model_provider_settings",
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
            openai_api_key = st.text_input(
                "Enter your OpenAI API key:",
                type="password",
                help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
                key="openai_api_key_settings"
            )
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                key="selected_model_settings",
                help="OpenAI have moved to continuous model upgrades so `gpt-3.5-turbo`, `gpt-4` and `gpt-4-turbo` point to the latest available version of each model.",
            )

        # Similar blocks for Azure OpenAI Service, Google AI API, and Mistral API

    elif selected == "About":
        st.title("About")
        st.markdown("""
        Welcome to adversys, an AI-powered tool designed to help teams produce better threat models for their applications. Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. adversys aims to help teams produce more comprehensive threat models by leveraging the power of Large Language Models (LLMs) to generate a threat list, attack tree and/or mitigating controls for an application based on the details provided. Created by Haydar Majeed.

        Below is an example application description that you can use to test adversys:

        > A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users.

        ### FAQs
        """)

        with st.expander("What is adversys?"):
            st.write("adversys is an AI-powered tool that helps teams produce better threat models for their applications.")

        with st.expander("How to perform Threat Modeling ith adversys?"):
            st.write("Provide a description of the application and the type of authentication it uses (e.g. OAuth2, JWT, etc.). Below is an example application description that you can use to test adversys:") 
            st.write("""
            > A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users.
            """)

        with st.expander("What should I upload to speedup the threat modeling process?"):
            st.write("Uploading an architecture diagram of the application you are threat modeling will help us understand the application better and generate a more accurate threat model.")

        with st.expander("What framework is used to create the threat model?"):
            st.write("adversys leverages the STRIDE framework to create the threat model.")

        with st.expander("What is STRIDE?"):
            st.write("""
            STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. 
            It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.
            """)

        with st.expander("How does adversys work?"):
            st.write("""
            When you enter an application description and other relevant details, the tool will use a GPT model to generate a threat model for your application. 
            The model uses the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.
            """)

        with st.expander("Do you store the application details provided?"):
            st.write("No, adversys does not store your application description or other details. All entered data is deleted after you close the browser tab.")

        with st.expander("Why does it take so long to generate a threat model?"):
            st.write("""
            If you are using a free OpenAI API key, it will take a while to generate a threat model. This is because the free API key has strict rate limits. 
            To speed up the process, you can use a paid API key.
            """)

        with st.expander("Are the threat models 100% accurate?"):
            st.write("""
            No, the threat models are not 100% accurate. adversys uses GPT Large Language Models (LLMs) to generate its output. The GPT models are powerful, 
            but they sometimes make mistakes and are prone to 'hallucinations' (generating irrelevant or inaccurate content). 
            Please use the output only as a starting point for identifying and addressing potential security risks in your applications.
            """)

        with st.expander("How can I improve the accuracy of the threat models?"):
            st.write("""
            You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, 
            authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.
            """)
    elif selected == "Copilot":

        # Title of the page
        st.title("Copilot Page")

        # Define sections with appropriate spacing and headers

        # Chats section
        st.subheader("Chats")
        if "history" not in st.session_state:
            st.session_state.history = []

        st.text("(Chat list would appear here)")
        st.markdown("---")  # Add a horizontal rule for separation

        # Chatbox section
        st.subheader("Chatbox")

        # Display chat history
        chat_history_container = st.container()
        with chat_history_container:
            for speaker, message in st.session_state.history:
                st.markdown(f"**{speaker}**: {message}")

        # Chat input and send button
        chat_input = st.text_input("Send a message...", key="chat_input")
        send_button = st.button("Send", key="send_button")

        if send_button and chat_input:
            history_text = "\n".join([f"{speaker}: {message}" for speaker, message in st.session_state.history])
            result, updated_history = ui_ops.handle_text_submission(chat_input, history_text)
            
            st.session_state.history.append(("User", chat_input))
            st.session_state.history.append(("Bot", result))

            # Update chat history
            with chat_history_container:
                st.markdown(f"**User**: {chat_input}")
                st.markdown(f"**Bot**: {result}")
        st.markdown("---")  # Add a horizontal rule for separation

        # Local Docs section
        st.subheader("Local Docs")
        uploaded_file = st.file_uploader("Add Docs")
        if uploaded_file:
            add_data(uploaded_file)
            st.success("Document added successfully")
            st.text("Select a collection to make it available to the chat model")
    else:
        st.title(f"{selected} Page")
        st.write("This page is under construction.")

if __name__ == "__main__":
    main()
