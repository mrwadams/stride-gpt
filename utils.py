import re
import json

def extract_deepseek_reasoning(response_text):
    """
    Extract reasoning and final output from DeepSeek R1 model response.
    The reasoning is contained within <think></think> tags.
    
    Args:
        response_text (str): The raw response text from the model
        
    Returns:
        tuple: (reasoning, final_output)
            - reasoning: The extracted reasoning text, or None if no reasoning found
            - final_output: The remaining text after removing the reasoning
    """
    # Look for content within <think></think> tags
    think_pattern = r'<think>(.*?)</think>'
    think_match = re.search(think_pattern, response_text, re.DOTALL)
    
    if think_match:
        reasoning = think_match.group(1).strip()
        # Remove the think tags and their content to get the final output
        final_output = re.sub(think_pattern, '', response_text, flags=re.DOTALL).strip()
        return reasoning, final_output
    else:
        # If no think tags found, return None for reasoning and the original text as final output
        return None, response_text

def extract_mermaid_code(text):
    """
    Extract the Mermaid diagram code from text that may contain additional content.
    Looks for code between ```mermaid, ``` or just ``` tags, and extracts the graph content.
    Also cleans and validates the Mermaid syntax.
    
    Args:
        text (str): The text containing the Mermaid code
        
    Returns:
        str: The cleaned Mermaid code, or the original text if no code block is found
    """
    # Try to find code block with explicit mermaid tag
    mermaid_pattern = r'```mermaid\s*(graph[\s\S]*?)```'
    match = re.search(mermaid_pattern, text, re.MULTILINE)
    
    if not match:
        # Try to find any code block containing graph definition
        code_pattern = r'```\s*(graph[\s\S]*?)```'
        match = re.search(code_pattern, text, re.MULTILINE)
    
    if match:
        # Extract just the graph content
        code = match.group(1).strip()
    else:
        # If no code block found but text contains graph definition, use as is
        code = text.strip()
    
    # Only proceed if we have a graph definition
    if not code.startswith('graph '):
        if 'graph ' in code:
            # Find the start of the graph definition
            code = code[code.find('graph '):]
        else:
            return text

    # Clean up common issues in Mermaid syntax
    code = clean_mermaid_syntax(code)
    
    return code

def clean_mermaid_syntax(code):
    """
    Clean up common issues in Mermaid syntax.
    
    Args:
        code (str): The Mermaid code to clean
        
    Returns:
        str: The cleaned Mermaid code
    """
    # Ensure proper spacing around arrows
    code = re.sub(r'(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)', r'\1 \2 \3', code)
    
    # Fix missing brackets around node labels
    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in '[](){}'):
            return f'{node_id}[{node_id}]'
        return node_id
    code = re.sub(r'(?:^|\s)(\w+)(?:\s|$)', fix_node_brackets, code)
    
    # Ensure node IDs with spaces are properly quoted
    def quote_node_labels(match):
        label = match.group(1)
        if ' ' in label and not label.startswith('"'):
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', quote_node_labels, code)
    
    # Fix parentheses in node labels
    def fix_parentheses(match):
        label = match.group(1)
        if '(' in label or ')' in label:
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', fix_parentheses, code)
    
    # Ensure proper line endings
    code = code.replace('\r\n', '\n').strip()
    
    return code

def process_groq_response(response_text, model_name, expect_json=True):
    """
    Process a Groq API response, handling special cases for different models.
    
    Args:
        response_text (str): The raw response text from the model
        model_name (str): The name of the model used
        expect_json (bool): Whether the response is expected to be JSON
        
    Returns:
        tuple: (reasoning, processed_output)
            - reasoning: The extracted reasoning if available, otherwise None
            - processed_output: The processed final output (parsed JSON if expect_json=True)
    """
    reasoning = None
    final_output = response_text
    
    # Handle DeepSeek R1 model's special case
    if model_name == "deepseek-r1-distill-llama-70b":
        reasoning, final_output = extract_deepseek_reasoning(response_text)
    
    # Process the final output based on whether we expect JSON
    if expect_json:
        try:
            processed_output = json.loads(final_output)
        except json.JSONDecodeError as e:
            # If JSON parsing fails, return the raw text
            processed_output = final_output
    else:
        # For non-JSON responses, check if it's a Mermaid diagram
        if 'graph ' in final_output:
            processed_output = extract_mermaid_code(final_output)
        else:
            processed_output = final_output
    
    return reasoning, processed_output

def create_reasoning_system_prompt(task_description, approach_description):
    """
    Creates a system prompt formatted for OpenAI's reasoning models (o1, o3, o3-mini, o4-mini).
    
    Args:
        task_description (str): Description of what the model needs to do
        approach_description (str): Step-by-step approach the model should follow
        
    Returns:
        str: Formatted system prompt
    """
    return f"""Task: {task_description}

Approach:
{approach_description}""" 