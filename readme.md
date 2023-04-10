# STRIDE GPT

STRIDE GPT is an AI-powered threat modeling tool that leverages OpenAI's GPT-3 model to generate threat models for a given application based on the STRIDE methodology. Users provide application details, such as the application type, authentication methods, and whether the application is internet-facing or processes sensitive data. The GPT-3 model then generates a threat model based on the provided information.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features
- Simple and user-friendly interface
- Generates threat models based on the STRIDE methodology
- Utilises OpenAI's powerful GPT-3 model for AI-driven threat analysis
- No data storage; application details are not saved

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

## Usage

1. Run the Streamlit app:

```
streamlit run app.py
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