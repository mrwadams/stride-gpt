import re
import requests
import streamlit as st
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
from groq import Groq
from utils import process_groq_response, create_reasoning_system_prompt
import json
from google import genai as google_genai

# Function to create a prompt to generate a Data Flow Diagram
def create_dfd_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

Based on the above application details, create a comprehensive Data Flow Diagram (DFD) that shows:
1. External entities (users, systems, services)
2. Processes (application components, services)
3. Data stores (databases, caches, files)
4. Data flows between components
5. Trust boundaries where applicable

The DFD should help understand the system architecture and identify potential threat boundaries for security analysis.
"""
    return prompt

def create_dfd_mermaid_prompt():
    """
    Creates a prompt for generating DFD in Mermaid flowchart format.
    """
    return """Your task is to analyze the application and create a Data Flow Diagram (DFD) using Mermaid flowchart syntax.

Create a comprehensive DFD that shows:
- External entities (users, external systems)
- Processes (application components, services, functions)
- Data stores (databases, caches, files, sessions)
- Data flows between components with descriptive labels
- Trust boundaries using subgraphs where security boundaries exist

CRITICAL SYNTAX RULES:
- Node IDs must be simple alphanumeric (User, WebApp, DB1, API2)
- Node labels with spaces MUST be in quotes: User["External User"]
- NO parentheses in node labels - use dashes instead
- Data flow labels MUST be short and simple: -->|"Login"| or -->|"Data"|
- NO line breaks or newlines within labels
- Flow labels should be 1-3 words maximum
- Comments start with %% and should be minimal
- Use simple subgraph names: subgraph Internal
- Each line must be complete - no wrapping across lines

Node types:
- External entities: User["External User"]
- Processes: WebApp("Web Server")
- Data stores: DB[("Database")]
- Data flows: A -->|"Data"| B (keep labels SHORT)

Example format:
```mermaid
flowchart TD
    User["External User"]
    WebApp("Web Application")
    API("API Server")
    DB[("Database")]
    Cache[("Cache")]
    
    User -->|"Login"| WebApp
    WebApp -->|"API Call"| API
    API -->|"Query"| DB
    API -->|"Store"| Cache
    Cache -->|"Session"| API
    DB -->|"Data"| API
    API -->|"Response"| WebApp
    WebApp -->|"UI"| User
    
    subgraph Internal ["Internal Network"]
        API
        DB
        Cache
    end
```

ONLY RESPOND WITH THE MERMAID FLOWCHART CODE, NO ADDITIONAL TEXT."""

def extract_mermaid_dfd(response_text):
    """
    Extract Mermaid flowchart code from response text.
    """
    # Look for mermaid code blocks
    mermaid_pattern = r'```mermaid\s*(.*?)\s*```'
    match = re.search(mermaid_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # Look for flowchart code blocks
    flowchart_pattern = r'```flowchart\s*(.*?)\s*```'
    match = re.search(flowchart_pattern, response_text, re.DOTALL)
    if match:
        return f"flowchart TD\n{match.group(1).strip()}"
    
    # Look for code blocks without language specification
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        if 'flowchart' in code or '-->' in code:
            return code
    
    # If no code blocks found, return the whole response if it looks like Mermaid
    if 'flowchart' in response_text and '-->' in response_text:
        return response_text.strip()
    
    # Fallback: return cleaned response
    return response_text.strip()

def validate_mermaid_dfd(mermaid_code):
    """
    Basic validation of Mermaid DFD code.
    """
    if not mermaid_code:
        return False
    
    # Check for basic Mermaid flowchart structure
    if 'flowchart' not in mermaid_code.lower():
        return False
    
    # Check for data flow arrows
    if '-->' not in mermaid_code:
        return False
    
    return True

def get_dfd(api_key, model_name, prompt):
    """
    Generate DFD using OpenAI models.
    """
    client = OpenAI(api_key=api_key)

    # For reasoning models, use structured approach
    if model_name in ["gpt-5", "gpt-5-mini", "gpt-5-nano", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Create a comprehensive Data Flow Diagram (DFD) showing system components and data flows.",
            approach_description="""Analyze the application and create a Data Flow Diagram using Mermaid flowchart syntax.

Rules:
- Show external entities, processes, data stores, and data flows
- Use appropriate Mermaid node types for different components
- Include descriptive labels for data flows
- Add trust boundaries using subgraphs where applicable
- Focus on security-relevant data flows and boundaries

The DFD should help with threat modeling by clearly showing:
1. Where data enters and exits the system
2. How data flows between components
3. Where data is stored and processed
4. Trust boundaries and security perimeters"""
        )
        
        # Use max_completion_tokens for reasoning models
        response = client.chat.completions.create(
            model=model_name,
            max_completion_tokens=20000 if model_name.startswith("gpt-5") else 4000,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{prompt}\n\n{create_dfd_mermaid_prompt()}"}
            ]
        )
        response_content = response.choices[0].message.content
    else:
        # For standard models
        system_prompt = create_dfd_mermaid_prompt()
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        response_content = response.choices[0].message.content

    mermaid_code = extract_mermaid_dfd(response_content)
    
    # Less strict validation - just check if we got some content
    if mermaid_code and mermaid_code.strip():
        return mermaid_code
    else:
        # If extraction failed, try to return raw response if it looks like Mermaid
        if '-->' in response_content:
            return response_content
        # Last fallback: return raw response
        return response_content

def get_dfd_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    """
    Generate DFD using Azure OpenAI.
    """
    client = AzureOpenAI(
        azure_endpoint=azure_api_endpoint,
        api_key=azure_api_key,
        api_version=azure_api_version,
    )

    system_prompt = create_dfd_mermaid_prompt()
    response = client.chat.completions.create(
        model=azure_deployment_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    return extract_mermaid_dfd(response.choices[0].message.content)

def get_dfd_mistral(mistral_api_key, mistral_model, prompt):
    """
    Generate DFD using Mistral AI.
    """
    client = Mistral(api_key=mistral_api_key)

    system_prompt = create_dfd_mermaid_prompt()
    response = client.chat.complete(
        model=mistral_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    return extract_mermaid_dfd(response.choices[0].message.content)

def get_dfd_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Generate DFD using Ollama.
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/generate"
    
    full_prompt = f"{create_dfd_mermaid_prompt()}\n\n{prompt}"
    
    data = {
        "model": ollama_model,
        "prompt": full_prompt,
        "stream": False
    }
    
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        return extract_mermaid_dfd(result.get('response', ''))
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error communicating with Ollama: {e}")
        return None

def get_dfd_anthropic(anthropic_api_key, anthropic_model, prompt):
    """
    Generate DFD using Anthropic Claude.
    """
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model

    system_prompt = create_dfd_mermaid_prompt()
    
    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4000,
                thinking={
                    "type": "enabled",
                    "budget_tokens": 2000
                },
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Display thinking content in an expander if available
            if hasattr(response, 'thinking') and response.thinking and hasattr(response.thinking, 'content'):
                with st.expander("🧠 Claude's Reasoning Process", expanded=False):
                    st.write(response.thinking.content)
                    
        else:
            response = client.messages.create(
                model=anthropic_model,
                max_tokens=4000,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

        return extract_mermaid_dfd(response.content[0].text)
        
    except Exception as e:
        st.error(f"Error with Anthropic API: {e}")
        return None

def get_dfd_lm_studio(lm_studio_endpoint, model_name, prompt):
    """
    Generate DFD using LM Studio.
    """
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    system_prompt = create_dfd_mermaid_prompt()
    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    return extract_mermaid_dfd(response.choices[0].message.content)

def get_dfd_groq(groq_api_key, groq_model, prompt):
    """
    Generate DFD using Groq.
    """
    client = Groq(api_key=groq_api_key)

    system_prompt = create_dfd_mermaid_prompt()
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, content = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=False
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("🧠 Model Reasoning", expanded=False):
            st.write(reasoning)

    return extract_mermaid_dfd(content if content else response.choices[0].message.content)

def get_dfd_google(google_api_key, google_model, prompt):
    """
    Generate DFD using Google Gemini.
    """
    client = google_genai.Client(api_key=google_api_key)
    system_instruction = create_dfd_mermaid_prompt()

    try:
        try:
            from google.genai import types as google_types
            response = client.models.generate_content(
                model=google_model,
                contents=[prompt],
                config=google_types.GenerateContentConfig(system_instruction=system_instruction)
            )
        except Exception:
            # Fallback for older Google GenAI SDK versions
            response = client.models.generate_content(
                model=google_model,
                contents=[f"{system_instruction}\n\n{prompt}"]
            )

        return extract_mermaid_dfd(response.text)
        
    except Exception as e:
        st.error(f"Error with Google AI API: {e}")
        return None

# DFD Analysis Functions for Input Processing

def create_dfd_analysis_prompt():
    """
    Creates a prompt for analyzing uploaded DFD images or text.
    """
    return """Analyze this Data Flow Diagram (DFD) and extract key information about the system architecture.

Please identify and describe:

1. **External Entities**: Users, external systems, third-party services
2. **Processes**: Application components, services, functions, systems
3. **Data Stores**: Databases, caches, files, sessions, storage systems
4. **Data Flows**: How information moves between components
5. **Trust Boundaries**: Security perimeters, network boundaries
6. **Key Security Considerations**: Sensitive data flows, authentication points, external interfaces

Based on this analysis, provide a comprehensive application description that includes:
- System architecture and components
- Data flow patterns and processing
- External interfaces and dependencies
- Security-relevant boundaries and controls
- Authentication and data handling approaches

Format your response as a detailed application description suitable for threat modeling."""

def analyze_dfd_image(api_key, model_name, image_data, media_type, provider="openai"):
    """
    Analyze a DFD image and extract system information.
    """
    analysis_prompt = create_dfd_analysis_prompt()
    
    try:
        if provider == "openai":
            from threat_model import get_image_analysis
            result = get_image_analysis(api_key, model_name, analysis_prompt, image_data)
            if result and 'choices' in result:
                return result['choices'][0]['message']['content']
        
        elif provider == "google":
            from threat_model import get_image_analysis_google
            result = get_image_analysis_google(api_key, model_name, analysis_prompt, image_data)
            if result and 'choices' in result:
                return result['choices'][0]['message']['content']
        
        elif provider == "anthropic":
            from threat_model import get_image_analysis_anthropic
            result = get_image_analysis_anthropic(api_key, model_name, analysis_prompt, image_data, media_type)
            if result and 'choices' in result:
                return result['choices'][0]['message']['content']
        
        elif provider == "azure":
            from threat_model import get_image_analysis_azure
            # Azure parameters would need to be passed separately
            pass
            
        return None
        
    except Exception as e:
        st.error(f"Error analyzing DFD image: {e}")
        return None

def analyze_dfd_text(mermaid_text):
    """
    Analyze Mermaid DFD text and extract system information.
    """
    if not mermaid_text or not mermaid_text.strip():
        return None
    
    try:
        # Parse the Mermaid text to extract components
        lines = mermaid_text.split('\n')
        
        entities = []
        processes = []
        data_stores = []
        flows = []
        subgraphs = []
        
        current_subgraph = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%%'):
                continue
                
            # Extract subgraphs (trust boundaries)
            if line.startswith('subgraph'):
                import re
                match = re.search(r'subgraph\s+(\w+)\s*\[?"?([^"]*)"?\]?', line)
                if match:
                    subgraph_id, subgraph_name = match.groups()
                    current_subgraph = subgraph_name or subgraph_id
                    subgraphs.append(current_subgraph)
                continue
            
            if line == 'end':
                current_subgraph = None
                continue
            
            # Extract node definitions
            if '[' in line and ']' in line:
                import re
                # Pattern for different node types
                # External entities: User["External User"]
                # Processes: WebApp("Web Server") 
                # Data stores: DB[("Database")]
                
                entity_pattern = r'(\w+)\["([^"]+)"\]'
                process_pattern = r'(\w+)\("([^"]+)"\)'
                datastore_pattern = r'(\w+)\[\("([^"]+)"\)\]'
                
                if re.search(datastore_pattern, line):
                    match = re.search(datastore_pattern, line)
                    if match:
                        node_id, label = match.groups()
                        data_stores.append(f"{label} ({node_id})")
                elif re.search(process_pattern, line):
                    match = re.search(process_pattern, line)
                    if match:
                        node_id, label = match.groups()
                        processes.append(f"{label} ({node_id})")
                elif re.search(entity_pattern, line):
                    match = re.search(entity_pattern, line)
                    if match:
                        node_id, label = match.groups()
                        entities.append(f"{label} ({node_id})")
            
            # Extract flows
            if '-->' in line:
                import re
                flow_pattern = r'(\w+)\s*-->\s*\|"?([^"|]+)"?\|\s*(\w+)'
                match = re.search(flow_pattern, line)
                if match:
                    from_node, flow_label, to_node = match.groups()
                    flows.append(f"{from_node} -> {to_node}: {flow_label}")
        
        # Generate description from extracted components
        description_parts = []
        
        if entities:
            description_parts.append(f"External Entities: {', '.join(entities)}")
        
        if processes:
            description_parts.append(f"System Components: {', '.join(processes)}")
            
        if data_stores:
            description_parts.append(f"Data Stores: {', '.join(data_stores)}")
            
        if flows:
            description_parts.append(f"Key Data Flows: {'; '.join(flows[:10])}")  # Limit to first 10 flows
            
        if subgraphs:
            description_parts.append(f"Trust Boundaries: {', '.join(subgraphs)}")
        
        if description_parts:
            return "System Architecture Analysis:\n\n" + "\n\n".join(description_parts)
        else:
            return "Unable to parse DFD structure from the provided text."
            
    except Exception as e:
        return f"Error analyzing DFD text: {str(e)}"