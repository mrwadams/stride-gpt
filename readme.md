![STRIDE GPT Logo](logo.png)

STRIDE GPT is an AI-powered threat modeling tool that leverages OpenAI's GPT models to generate threat models and attack trees for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The GPT model then generates its output based on the provided information.

## Table of Contents
- [Star the Repo](#star-the-repo)
- [Features](#features)
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
- Generates attack trees to enumerate possible attack paths
- Suggests possible mitigations for identified threats
- Utilises OpenAI's powerful GPT models for AI-driven threat analysis
- No data storage; application details are not saved

## Changelog

### Version 0.3

In this version I've made significant improvements to the application to enhance its functionality and usability. Here are the key highlights of this release:

- **Threat Mitigations**: STRIDE GPT can now suggest potential mitigations for the threats identified in the threat modelling phase. This helps users develop strategies to prevent or minimise the impact of the identified threats.
- **Downloadable Output**: Users can now download the generated threat model, attack tree, and mitigations as Markdown files directly from the application. This makes it easy to share and document the generated outputs.
- **Improved User Interface**: I've further refined the user interface to provide a smoother and more intuitive user experience. The application layout has been optimised for better readability and usability.
- **Updated GPT Models**: STRIDE GPT now supports the latest 0613 versions of the GPT-3.5-turbo and GPT-4 models. These updated models provide improved performance and increased control over the generated output.
- **Bug Fixes and Performance Enhancements**: I've addressed several bugs and made performance improvements to ensure a more stable and responsive application.

I hope these updates make STRIDE GPT an even more valuable tool for your threat modeling needs. I appreciate your continued support and welcome your feedback for further improvements.


### Version 0.2

Release highlights:

- **Attack Tree Generation**: In addition to generating threat models, STRIDE GPT can now generate attack trees for your applications based on the provided details. This helps users better understand potential attack paths for their applications.
- **Attack Tree Visualisation**: This is an experimental feature that allows users to visualise the generated attack tree directly in the app using Mermaid.js. This provides a more interactive experience within the STRIDE GPT interface.
- **GPT-4 Model Support**: STRIDE GPT now supports the use of OpenAI's GPT-4 model, provided the user has access to the GPT-4 API. This allows users to leverage the latest advancements in GPT technology to generate more accurate and comprehensive threat models and attack trees.
- **Improved Layout and Organisation**: I've restructured the app layout to make it easier to navigate and use. Key sections, such as Threat Model and Attack Tree, are now organised into collapsible sections for a cleaner and more intuitive user experience.


### Version 0.1

Initial release of the application.

## Installation

1. Clone this repository:

```
git clone https://github.com/mrwadams/stride-gpt.git
```

2. Change to the cloned repository directory:

```
cd stride-gpt
```

3. Install the required Python packages:

```
pip install -r requirements.txt
```

**Note:** 📝 Streamlit should **not** be included in requirements.txt as it causes the Streamlit deployment process to fail.

## Usage

1. Run the Streamlit app:

```
streamlit run main.py
```

2. Open the app in your web browser using the provided URL.

3. Enter your OpenAI API key in the sidebar.

4. Provide the application details and select the appropriate options.

5. Navigate to the Threat Model and/or Attack Tree section and click the "Generate..." button.

6. Review the generated threat model and/or attack tree and, if required, download a markdown copy of the output.

7. If you want to generate suggested mitigations for the identified threats, go to the "Mitigations" section and click the "Suggest Mitigations" button.

8. Review the suggested mitigations and, if required, download them as a Markdown file.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)