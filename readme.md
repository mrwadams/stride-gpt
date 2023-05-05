# STRIDE GPT

STRIDE GPT is an AI-powered threat modeling tool that leverages OpenAI's GPT-3 model to generate threat models for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The GPT-3 model then generates a threat model based on the provided information.

## Table of Contents
- [Features](#features)
- [Changelog](#changelog)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features
- Simple and user-friendly interface
- Generates threat models based on the STRIDE methodology
- Generates attack trees to enumerate possible attack paths
- Utilises OpenAI's powerful GPT models for AI-driven threat analysis
- No data storage; application details are not saved

## Changelog

### Version 2.0

In this major update I've introduced several new features and improvements that make STRIDE GPT even more powerful and user-friendly. Here are the key highlights of this release:

- **Attack Tree Generation**: In addition to generating threat models, STRIDE GPT can now generate attack trees for your applications based on the provided details. This helps users better understand potential attack paths for their applications.
- **Attack Tree Visualisation**: This is an experimental feature that allows users to visualise the generated attack tree directly in the app using Mermaid.js. This provides a more interactive experience within the STRIDE GPT interface.
- **GPT-4 Model Support**: STRIDE GPT now supports the use of OpenAI's GPT-4 model, provided the user has access to the GPT-4 API. This allows users to leverage the latest advancements in GPT technology to generate more accurate and comprehensive threat models and attack trees.
- **Improved Layout and Organisation**: I've restructured the app layout to make it easier to navigate and use. Key sections, such as Threat Model and Attack Tree, are now organised into collapsible sections for a cleaner and more intuitive user experience.

I hope these updates make STRIDE GPT an even more valuable tool for your threat modeling needs. As always, I welcome your feedback and suggestions for future improvements.

### Version 1.0

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

5. Click "Submit" to generate the threat model.

6. Review the generated threat model and use the "Copy to Clipboard" button to copy the results.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update the tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)