def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
    Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description and additional provided to you to produce a list of specific threats for the application.

    For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

    When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact". 

    Under "improvement_suggestions", include an array of strings with suggestions on how the threat modeller can improve their application description in order to allow the tool to produce a more comprehensive threat model.

    APPLICATION TYPE: {app_type}
    AUTHENTICATION METHODS: {authentication}
    INTERNET FACING: {internet_facing}
    SENSITIVE DATA: {sensitive_data}
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
