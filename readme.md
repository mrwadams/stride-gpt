![STRIDE GPT Logo](logo.png)

STRIDE GPT is an AI-powered threat modelling tool that leverages Large Language Models (LLMs) to generate threat models and attack trees for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The model then generates its output based on the provided information.

## Table of Contents
- [Star the Repo](#star-the-repo)
- [Features](#features)
- [Enterprise Deployment](#enterprise-deployment)
- [Roadmap](#roadmap)
- [Talk at Open Security Summit](#talk-at-open-security-summit)
- [Changelog](#changelog)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Support the Project

If you find STRIDE GPT useful, please consider supporting the project:

- ⭐ **Star the repository** on GitHub to help more people discover the tool
- ☕ **Buy me a coffee** to support continued development and maintenance

<a href="https://buymeacoffee.com/mrwadams" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px; width: 217px;">
</a>

## Features
- Simple and user-friendly interface
- Generates threat models based on the STRIDE methodology
- Multi-modal: Use architecture diagrams, flowcharts, etc. as inputs for threat modelling across all supported vision-capable models
- Generates attack trees to enumerate possible attack paths
- Suggests possible mitigations for identified threats
- Supports DREAD risk scoring for identified threats
- Generates Gherkin test cases based on identified threats
- GitHub repository analysis for comprehensive threat modelling (including GitHub Enterprise support)
- Advanced reasoning model support (OpenAI GPT-5 series, Anthropic Claude 4, Mistral Magistral series)
- Comprehensive LLM provider support: OpenAI, Azure OpenAI, Anthropic, Google AI, Mistral, Groq, plus local hosting via Ollama and LM Studio Server
- No data storage; application details are not saved
- Available as a Docker container image for easy deployment
- Environment variable support for secure configuration
- Downloadable outputs in Markdown format for all generated content

## Enterprise Deployment

Want to customize STRIDE-GPT for your organization? Check out our comprehensive [Operationalization Guide](docs/operationalization-guide.md) to learn how to:

- 🎯 Inject organizational security controls and standards
- 📋 Customize threat models with your compliance requirements
- 🔧 Fork and deploy STRIDE-GPT internally
- 📊 Get context-aware, actionable threat models specific to your environment

The guide includes step-by-step instructions, code examples, and deployment patterns for organizations looking to scale AI-powered threat modeling across their teams.

## Roadmap
- [x] Add support for multi-modal threat modelling
- [x] Autogenerate application descriptions based on README files in GitHub repositories
- [ ] Customisable and exportable reports (e.g. PDF, Word) that include the generated threat model, attack tree, and mitigations
- [ ] Add a helper tool to guide users to create effective application descriptions before generating threat models
- [ ] Update UI to support multiple languages

## Talk at Open Security Summit

In January 2024 I gave a talk about STRIDE GPT at the [Open Security Summit](https://open-security-summit.org/sessions/2024/mini-summits/jan/threat-modeling/ai-driven-threat-modelling-with-stride-gpt/). During the talk, I discussed the project's inception, its core functionalities, recent updates, and some future plans. You can watch the full presentation below:

[![Open Security Summit Talk](https://i3.ytimg.com/vi/_eOcezCeM1M/maxresdefault.jpg)](https://youtu.be/_eOcezCeM1M?si=88bjQ2M-_sCyIioi)

This video is an excellent resource for anyone interested in understanding how STRIDE GPT works and how it can be used to improve threat modelling.

## Changelog

### Version 0.14 (latest)

- **GPT-5 Series Support**: Added comprehensive support for OpenAI's GPT-5 series models (gpt-5, gpt-5-mini, gpt-5-nano) across all threat modeling features. These advanced reasoning models provide enhanced analytical capabilities with proper token allocation for both internal reasoning and output generation.
- **Anthropic Claude 4 Integration**: Added support for Anthropic's latest Claude 4 models (claude-opus-4-1-20250805, claude-opus-4-20250514, and claude-sonnet-4-20250514) with enhanced capabilities.
- **GitHub Enterprise Support**: Added support for GitHub Enterprise repositories. The tool now automatically detects and configures the appropriate API endpoint based on the repository URL, making it easy to analyze repositories hosted on private GitHub Enterprise instances. (Thanks to @danielpops for the contribution!)
- **Enhanced Reasoning Model Integration**: Updated parameter handling to use `max_completion_tokens` instead of deprecated `max_tokens` for GPT-5 and other OpenAI reasoning models, ensuring compatibility with OpenAI's latest API requirements.
- **Improved DREAD Assessment Display**: Removed truncation limits in DREAD assessment scenario descriptions, allowing users to view complete threat scenarios in the risk assessment table instead of abbreviated "..." versions.
- **Security Updates**: Updated dependencies to address security vulnerabilities identified by Snyk, including updates to anyio, zipp, tornado, requests, and urllib3.
- **Mistral Model Updates**: Added support for Mistral's latest models including Magistral Medium/Small (reasoning models), Mistral Medium, and Ministral 8B.
- **Groq Model Updates**: Updated Groq model selection with OpenAI GPT-OSS models (120B, 20B), maintained Llama 3.3 70B and 3.1 8B, kept DeepSeek R1, and added Moonshot Kimi K2 and Qwen3 32B.
- **Google Gemini 2.5 GA Update**: Updated to use the General Availability versions of Gemini 2.5 models (Pro, Flash, Flash Lite) replacing the previous preview versions.
- **Support the Project**: Added a "Buy me a coffee" button in the sidebar to allow users to support the continued development and maintenance of STRIDE GPT.

### Version 0.13

- **New OpenAI Models**: Added support for OpenAI's latest models: gpt-4.1, o3, and o4-mini while maintaining support for o3-mini. These reasoning models provide detailed analytical capabilities.
- **Migrated to New Google GenAI SDK**: Completely migrated to the new Google GenAI SDK, removing all dependency on the deprecated Google Generative AI library. Refactored Gemini (Google AI) model integration across all modules for improved consistency and performance.
- **Enhanced Reasoning Model Support**: Expanded the reasoning framework to work with all of OpenAI's reasoning models (o1, o3, o3-mini, o4-mini) across all threat modeling features, including threat model generation, attack trees, mitigations, and DREAD assessments.
- **Increased Token Limits**: Updated token limits for new models to take advantage of their expanded contexts, particularly for gpt-4.1 which supports 1 million tokens and o4-mini which supports 200K tokens.
- **Enhanced Multi-Modal Support**: Image upload and analysis now works with more models, including Gemini 2.5, Claude 3, and Claude 4 models. Expanded support for analyzing various image formats across all vision-capable models.
- **Updated to Latest Gemini Preview Models**: Transitioned to use the latest versions of Gemini preview models for improved performance and capabilities.

### Version 0.12

- **Claude 3.7 Integration**: Added comprehensive support for Anthropic's Claude 3.7 models across all threat modeling features, including the innovative "thinking mode" that provides more detailed reasoning during analysis.
- **Improved GitHub Repository Analysis**: Significantly enhanced the GitHub repository analysis feature with intelligent file selection, better programming language support, and progress tracking during analysis.
- **GPT-4.5 Preview Support**: Added support for OpenAI's GPT-4.5 preview model with improved model selection guidance and descriptions.
- **Performance Optimizations**: Improved overall application performance with better token usage tracking and warning systems for approaching token limits.

### Version 0.11

- **LM Studio Server Support**: Added support for using LM Studio Server as a model provider, allowing users to run their own local LLMs with OpenAI-compatible API endpoints. This complements the existing Ollama integration for local model hosting.
- **Google Gemini Attack Tree Support**: Added support for generating attack trees using Google Gemini models, expanding the available options for users.
- **New Model Support**: Added support for reasoning models (OpenAI's o1 and o3-mini, DeepSeek R1 via Groq API) and Google's newly released Gemini 2.0 Flash for faster inference.
- **Enhanced Attack Tree Generation**: Improved attack tree generation with robust JSON parsing and Mermaid diagram conversion, making the output more reliable and visually appealing.
- **Dynamic Model Discovery**: Added automatic model discovery for both Ollama and LM Studio Server, allowing users to select from available models in their local instances.
- **Improved Threat Model Generation**: Enhanced the guidance and prompts for threat model generation to produce more comprehensive and actionable results.
- **Structured Output Support**: Enhanced JSON output handling across all model providers to ensure reliable threat model and DREAD assessment generation.
- **UI Enhancements**: Updated the user interface to accommodate new model configurations and improved warning messages for local LLM limitations.

### Version 0.10

- **GitHub Repository Analysis**: STRIDE GPT now supports automatic analysis of GitHub repositories. Users can provide a GitHub repository URL, and the tool will analyse the README and key files to generate a more comprehensive threat model.
- **Environment Variable Support**: Added support for loading API keys and other configuration from environment variables, improving security and ease of deployment.
- **Improved Error Handling**: Enhanced error handling and retry mechanisms for API calls to improve reliability.
- **UI Enhancements**: Updated the user interface to accommodate new features and improve overall user experience.

### Version 0.9

Release highlights:

- **Local Model Hosting**: STRIDE GPT now supports the use of locally hosted LLMs via an integration with Ollama. This feature is particularly useful for organisations with strict data privacy requirements or those who prefer to keep their data on-premises. Please note that this feature is not available for users of the STRIDE GPT version hosted on Streamlit Community Cloud at https://stridegpt.streamlit.app
- **Mistral Client v1.0**: STRIDE GPT now uses v1.0 of the Mistral Client, which resolves the breaking changes introduced in the latest version of the Mistral API. This ensures that STRIDE GPT users can continue to leverage the Mistral API for threat modelling tasks.

### Version 0.8.1

This release added support for the following models:

- **GPT4o mini**: I've added support for OpenAI's recently released GPT4o mini model. GPT4o mini is a cost-efficient small model that still provides high-quality responses for threat modelling tasks.

- **Gemini 1.5 Pro (stable)**: Users can now choose from either the stable or preview versions of the Gemini 1.5 Pro model.

<details>
  <summary>Click to view release notes for earlier versions.</summary>


### Version 0.8

Release highlights:

- **DREAD Risk Scoring**: STRIDE GPT now supports DREAD risk scoring, allowing users to assign risk scores to identified threats based on the DREAD model. This feature provides a more comprehensive threat assessment and helps prioritise mitigation efforts.

- **Gherkin Test Cases**: Users can now generate Gherkin test cases based on the identified threats. This feature helps bridge the gap between threat modelling and testing, ensuring that security considerations are integrated into the testing process.

- **UI Enhancements**: I've refreshed the user interface making it easier to navigate and interact with the application and its features.

### Version 0.7

Release highlights:

- **Multi-Modal Threat Modelling**: STRIDE GPT now supports multi-modal threat modelling using OpenAI's GPT-4o and GPT-4-Turbo models. Users can provide an image of an architecture diagram, flowchart, or other visual representations of their application to enhance the threat modelling process.
- **Google AI Integration**: I've added support for Gemini 1.5 Pro via the Google AI API. Please note that Gemini doesn't consistently generate JSON output so you may need to retry some requests. In addition, Attack Trees can't be generated using Google AI models because of Google's safety restrictions.
- **Refactored Codebase**: I've refactored some parts of the codebase to improve maintainability and readability. This should make it easier to add new features and enhancements in future releases.
- **Bug Fixes**: Minor bug fixes and error handling improvements.


### Version 0.6

Release highlights:

- **Mistral API Integration**: Users can now choose to use LLMs provided by Mistral AI to generate threat models, attack trees and mitigation suggestions. This provides an alternative to OpenAI's GPT models, offering greater flexibility and choice for users.

- **Refined Prompts**: With more people using STRIDE GPT for work, I've updated the threat model prompt templates to encourage the LLMs to generate more comprehensive outputs. Users should now see multiple threats identified within each STRIDE category.

- **Public Roadmap**: I've created a public roadmap to provide visibility into upcoming features and improvements.

- **UI Enhancements**: I've made some minor updates to the UI to accommodate the new Mistral API integration and improve the overall user experience.


### Version 0.5

Release highlights:

- **Azure OpenAI Service Integration**: Users can now opt to use OpenAI 1106-preview models hosted on the Azure OpenAI Service, in addition to the standard OpenAI API.
- **Docker Container Image**: To make it easier to deploy STRIDE GPT on public and private clouds, the tool is now available as a [Docker container image](https://hub.docker.com/repository/docker/mrwadams/stridegpt/general) on Docker Hub.

### Version 0.4

Release highlights:

- **Integration of New GPT Models**: The application now supports the latest "gpt-4-1106-preview" and "gpt-3.5-turbo-1106" models, offering advanced capabilities and more accurate responses for threat modelling and attack tree generation.
- **Direct OpenAI API Calls**: STRIDE GPT now makes direct calls to the OpenAI API in order to take advantage of the recently introduced JSON Mode. This should greatly reduce the reduce the likelihood of syntax errors when generating threat models.
- **Refined Attack Tree Generation**: The process for generating attack trees has been overhauled to be more reliable, minimising syntax errors when generating Mermaid diagrams and improving the overall quality of the visualisations.
- **New Logo and Color Scheme**: A refreshed colour scheme and new logo (generated by DALL·E 3).
- **Continued Bug Fixes and Performance Improvements**: I've made a small number of additional updates to address existing bugs and optimise the application for better performance, ensuring a smoother and more efficient user experience.

### Version 0.3

Release highlights:

- **Threat Mitigations**: STRIDE GPT can now suggest potential mitigations for the threats identified in the threat modelling phase. This helps users develop strategies to prevent or minimise the impact of the identified threats.
- **Downloadable Output**: Users can now download the generated threat model, attack tree, and mitigations as Markdown files directly from the application. This makes it easy to share and document the generated outputs.
- **Improved User Interface**: I've further refined the user interface to provide a smoother and more intuitive user experience. The application layout has been optimised for better readability and usability.
- **Updated GPT Models**: STRIDE GPT now supports the latest 0613 versions of the GPT-3.5-turbo and GPT-4 models. These updated models provide improved performance and increased control over the generated output.
- **Bug Fixes and Performance Enhancements**: I've addressed several bugs and made performance improvements to ensure a more stable and responsive application.

### Version 0.2

Release highlights:

   - **Attack Tree Generation**: In addition to generating threat models, STRIDE GPT can now generate attack trees for your applications based on the provided details. This helps users better understand potential attack paths for their applications.
   - **Attack Tree Visualisation**: This is an experimental feature that allows users to visualise the generated attack tree directly in the app using Mermaid.js. This provides a more interactive experience within the STRIDE GPT interface.
   - **GPT-4 Model Support**: STRIDE GPT now supports the use of OpenAI's GPT-4 model, provided the user has access to the GPT-4 API. This allows users to leverage the latest advancements in GPT technology to generate more accurate and comprehensive threat models and attack trees.
   - **Improved Layout and Organisation**: I've restructured the app layout to make it easier to navigate and use. Key sections, such as Threat Model and Attack Tree, are now organised into collapsible sections for a cleaner and more intuitive user experience.


### Version 0.1

   Initial release of the application.
</details>

## Installation

### Option 1: Cloning the Repository

1. Clone this repository:

    ```bash
    git clone https://github.com/mrwadams/stride-gpt.git
    ```

2. Change to the cloned repository directory:

    ```bash
    cd stride-gpt
    ```

3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

4. Set up environment variables:
   
   a. Copy the `.env.example` file to a new file named `.env`:
   ```
   cp .env.example .env
   ```
   
   b. Edit the `.env` file to add your API keys and/or endpoint URLs:
   ```
   GITHUB_API_KEY=your_actual_github_api_key
   OPENAI_API_KEY=your_actual_openai_api_key
   ANTHROPIC_API_KEY=your_actual_anthropic_api_key
   AZURE_API_KEY=your_actual_azure_api_key
   AZURE_API_ENDPOINT=your_actual_azure_endpoint
   AZURE_DEPLOYMENT_NAME=your_actual_azure_deployment_name
   GOOGLE_API_KEY=your_actual_google_api_key
   MISTRAL_API_KEY=your_actual_mistral_api_key
   OLLAMA_ENDPOINT=http://localhost:11434
   LM_STUDIO_ENDPOINT=http://localhost:1234
   ```

### Option 2: Using Docker Container

1. Pull the Docker image from Docker Hub:

    ```bash
    docker pull mrwadams/stridegpt:latest
    ```

2. Create a `.env` file with your API keys as described in step 4 of Option 1.

## Usage

### Option 1: Running the Streamlit App Locally

1. Run the Streamlit app:

    ```bash
    streamlit run main.py
    ```

2. Open the app in your web browser using the provided URL.

3. Follow the steps in the Streamlit interface to use STRIDE GPT.

### Option 2: Using Docker Container

1. Run the Docker container, mounting the `.env` file:

    ```bash
    docker run -p 8501:8501 --env-file .env mrwadams/stridegpt
    ```
    This command will start the container, map port 8501 (default for Streamlit apps) from the container to your host machine, and load the environment variables from the `.env` file.

2. Open a web browser and navigate to `http://localhost:8501` to access the app running inside the container.

3. Follow the steps in the Streamlit interface to use STRIDE GPT.

Note: When you run the application (either locally or via Docker), it will automatically load the environment variables you've set in the `.env` file. This will pre-fill the API keys in the application interface.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)