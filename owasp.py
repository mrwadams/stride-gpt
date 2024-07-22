def create_owasp_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
    Act as a cyber security expert with more than 20 years of experience in threat modeling using the OWASP (Open Web Application Security Project) methodology.
    Your task is to produce a threat model for the application described below.
    APPLICATION TYPE: {app_type}
    AUTHENTICATION METHODS: {authentication}
    INTERNET FACING: {internet_facing}
    SENSITIVE DATA: {sensitive_data}
    APPLICATION DESCRIPTION: {app_input}
    Use a JSON formatted response with keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact". 
    Under "improvement_suggestions", include an array of strings with suggestions on how the threat modeler can improve their application description.
    """
    return prompt
