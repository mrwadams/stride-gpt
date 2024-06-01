![STRIDE GPT Logo](logo.png)

STRIDE GPT is an AI-powered threat modelling tool that leverages Large Language Models (LLMs) to generate threat models and attack trees for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The model then generates its output based on the provided information.

## Table of Contents
- [Star the Repo](#star-the-repo)
- [Features](#features)
- [Roadmap](#roadmap)
- [Talk at Open Security Summit](#talk-at-open-security-summit)
- [Changelog](#changelog)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Star the Repo

If you find STRIDE GPT useful, please consider starring the repository on GitHub. This helps more people discover the tool. Your support is greatly appreciated! ⭐

## Features
- Simple and user-friendly interface
- Generates threat models based on the STRIDE methodology
- 🆕 Multi-modal: Use architecture diagrams, flowcharts, etc. as inputs for threat modelling 
- Generates attack trees to enumerate possible attack paths
- Suggests possible mitigations for identified threats
- No data storage; application details are not saved
- Supports models accessed via OpenAI API, Azure OpenAI Service, 🆕 Google AI API or Mistral API
- Available as a Docker container image for easy deployment

## Roadmap
- [x] Add support for multi-modal threat modelling
- [ ] Autogenerate application descriptions based on README files in GitHub repositories
- [ ] Customisable and exportable reports (e.g. PDF, Word) that include the generated threat model, attack tree, and mitigations
- [ ] Add a helper tool to guide users to create effective application descriptions before generating threat models
- [ ] Update UI to support multiple languages

## Talk at Open Security Summit

In January 2024 I gave a talk about STRIDE GPT at the [Open Security Summit](https://open-security-summit.org/sessions/2024/mini-summits/jan/threat-modeling/ai-driven-threat-modelling-with-stride-gpt/). During the talk, I discussed the project's inception, its core functionalities, recent updates, and some future plans. You can watch the full presentation below:

[![Open Security Summit Talk](https://i3.ytimg.com/vi/_eOcezCeM1M/maxresdefault.jpg)](https://youtu.be/_eOcezCeM1M?si=88bjQ2M-_sCyIioi)

This video is an excellent resource for anyone interested in understanding how STRIDE GPT works and how it can be used to improve threat modelling.

## Changelog

### Version 0.8 (latest)

Version 0.8 introduces new features and improvements that enhance STRIDE GPT's capabilities and user experience. Here's what's new:

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

<details>
  <summary>Click to view release notes for earlier versions.</summary>

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

### Option 2: Using Docker Container

1. Pull the Docker image from Docker Hub:

    ```bash
    docker pull mrwadams/stridegpt:latest
    ```

## Usage

### Option 1: Running the Streamlit App Locally

1. Run the Streamlit app:

    ```bash
    streamlit run main.py
    ```

2. Open the app in your web browser using the provided URL.

3. Follow the steps in the Streamlit interface to use STRIDE GPT.

### Option 2: Using Docker Container

1. Run the Docker container:

    ```bash
    docker run -p 8501:8501 mrwadams/stridegpt
    ```
    This command will start the container and map port 8501 (default for Streamlit apps) from the container to your host machine.

2. Open a web browser and navigate to `http://localhost:8501` to access the app running inside the container.

3. Follow the steps in the Streamlit interface to use STRIDE GPT.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)