import base64
import streamlit as st
import streamlit.components.v1 as components
from streamlit_option_menu import option_menu

from threat_model import (
    create_threat_model_prompt,
    get_threat_model,
    get_threat_model_azure,
    get_threat_model_google,
    get_threat_model_mistral,
    json_to_markdown,
    get_image_analysis,
    create_image_analysis_prompt,
)
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure, get_attack_tree_mistral
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google, get_mitigations_mistral
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google, get_test_cases_mistral
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, get_dread_assessment_mistral, dread_json_to_markdown

# ------------------ Helper Functions ------------------ #

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

# Function to create the sidebar
def create_sidebar():
    with st.sidebar:
        st.image("logo.png", width=100)  # Replace with your logo
        st.title("Blue Ship, Inc.")
        
        selected = option_menu(
            menu_title=None,
            options=[
                "Co-pilot", "Pen Test", "Threat Model",
                "RFPs", "Integrations", "Team", "Tutorials", "Settings"
            ],
            icons=[
                "chat-dots", "person", "file-earmark-text",
                "search", "globe", "people", "book", "gear"
            ],
            default_index=2,
            styles={
                "container": {"padding": "0!important", "background-color": "#4B9EFA"},
                "icon": {"color": "white", "font-size": "14px"},
                "nav-link": {
                    "color": "white",
                    "font-size": "14px",
                    "text-align": "left",
                    "margin": "0px",
                    "--hover-color": "#3D7BC7",
                },
                "nav-link-selected": {"background-color": "#3D7BC7"},
            },
        )
        
        st.caption("Ready for dev")
    
    return selected

# Main function
def main():
    st.set_page_config(
        page_title="adversys",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    
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
            
            # Existing Threat Model tab code

            model_provider = st.selectbox(
                "Select your preferred model provider:",
                ["OpenAI API", "Azure OpenAI Service", "Google AI API", "Mistral API"],
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
                # Add OpenAI API key input field
                openai_api_key = st.text_input(
                    "Enter your OpenAI API key:",
                    type="password",
                    help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
                    key="openai_api_key_tab"
                )
                # Add model selection input field
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
                # Add Azure OpenAI API key input field
                azure_api_key = st.text_input(
                    "Azure OpenAI API key:",
                    type="password",
                    help="You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
                    key="azure_api_key_tab"
                )
                # Add Azure OpenAI endpoint input field
                azure_api_endpoint = st.text_input(
                    "Azure OpenAI endpoint:",
                    help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
                    key="azure_api_endpoint_tab"
                )
                # Add Azure OpenAI deployment name input field
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
                # Add Google AI API key input field
                google_api_key = st.text_input(
                    "Enter your Google AI API key:",
                    type="password",
                    help="You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
                    key="google_api_key_tab"
                )
                # Add model selection input field
                google_model = st.selectbox(
                    "Select the model you would like to use:",
                    ["gemini-1.5-pro-latest"],
                    key="google_model_tab",
                )

            if model_provider == "Mistral API":
                st.markdown(
                    """
                    1. Enter your [Mistral API key](https://console.mistral.ai/api-keys/) and chosen model below 🔑
                    2. Provide details of the application that you would like to threat model  📝
                    3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
                    """
                )
                # Add Mistral API key input field
                mistral_api_key = st.text_input(
                    "Enter your Mistral API key:",
                    type="password",
                    help="You can generate a Mistral API key in the [Mistral console](https://console.mistral.ai/api-keys/).",
                    key="mistral_api_key_tab"
                )
                # Add model selection input field
                mistral_model = st.selectbox(
                    "Select the model you would like to use:",
                    ["mistral-large-latest", "mistral-small-latest"],
                    key="mistral_model_tab",
                )

            # Two column layout for the main app content
            col1, col2 = st.columns([1, 1])

            # Initialize app_input in the session state if it doesn't exist
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
                                            # Update app_input session state
                                            st.session_state['app_input'] = image_analysis_content
                                        else:
                                            st.error("Failed to analyze the image. Please check the API key and try again.")
                                    except KeyError as e:
                                        st.error("Failed to analyze the image. Please check the API key and try again.")
                                        print(f"Error: {e}")
                                    except Exception as e:
                                        st.error("An unexpected error occurred while analyzing the image.")
                                        print(f"Error: {e}")

                    # Use text_area with the session state value and update the session state on change
                    app_input = st.text_area(
                        label="Describe the application to be modelled",
                        value=st.session_state['app_input'],
                        key="app_input_widget",
                        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
                    )
                    # Update session state only if the text area content has changed
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
                threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

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
                            elif model_provider == "Mistral API":
                                model_output = get_threat_model_mistral(mistral_api_key, mistral_model, threat_model_prompt)

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
                if model_provider == "Mistral API" and mistral_model == "mistral-small-latest":
                    st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
                
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
                            elif model_provider == "Mistral API":
                                mermaid_code = get_attack_tree_mistral(mistral_api_key, mistral_model, attack_tree_prompt)

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
                                elif model_provider == "Mistral API":
                                    mitigations_markdown = get_mitigations_mistral(mistral_api_key, mistral_model, mitigations_prompt)

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
                                elif model_provider == "Mistral API":
                                    dread_assessment = get_dread_assessment_mistral(mistral_api_key, mistral_model, dread_assessment_prompt)
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
                                elif model_provider == "Mistral API":
                                    test_cases_markdown = get_test_cases_mistral(mistral_api_key, mistral_model, test_cases_prompt)

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
            ["OpenAI API", "Azure OpenAI Service", "Google AI API", "Mistral API"],
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

    else:
        st.title(f"{selected} Page")
        st.write("This page is under construction.")

if __name__ == "__main__":
    main()
