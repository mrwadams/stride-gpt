"""Prompt templates for LLM calls. Zero Streamlit imports."""

from __future__ import annotations


def create_reasoning_system_prompt(task_description: str, approach_description: str) -> str:
    """Creates a system prompt formatted for OpenAI's GPT-5 series models.

    Args:
        task_description: Description of what the model needs to do
        approach_description: Step-by-step approach the model should follow

    Returns:
        Formatted system prompt
    """
    return f"""Task: {task_description}

Approach:
{approach_description}"""


def create_image_analysis_prompt() -> str:
    """Creates a prompt for analyzing architecture diagrams."""
    return """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key
         components, their interactions, and any technologies used.

    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional
    discussion.

    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
    """


def create_json_structure_prompt() -> str:
    """Creates a prompt for generating attack tree data in JSON format."""
    return """Your task is to analyze the application and create an attack tree structure in JSON format.

The JSON structure should follow this format:
{
    "nodes": [
        {
            "id": "root",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "auth",
                    "label": "Gain Unauthorized Access",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "Exploit OAuth2 Vulnerabilities"
                        }
                    ]
                }
            ]
        }
    ]
}

Rules:
- Use simple IDs (root, auth, auth1, data, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure the JSON is properly formatted

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""


def create_attack_tree_schema() -> dict:
    """Creates a JSON schema for attack tree structure."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {"nodes": {"type": "array", "items": {"$ref": "#/$defs/node"}}},
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node",
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal",
                            },
                            "children": {"type": "array", "items": {"$ref": "#/$defs/node"}},
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False,
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }


def create_attack_tree_schema_lm_studio() -> dict:
    """Creates a non-recursive JSON schema for attack tree structure specifically for LM Studio.

    Limits the depth to 3 levels to avoid circular references.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "description": "Simple alphanumeric identifier for the root node",
                                },
                                "label": {
                                    "type": "string",
                                    "description": "Description of the attack vector or goal",
                                },
                                "children": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {
                                                "type": "string",
                                                "description": "Simple alphanumeric identifier for the level 1 node",
                                            },
                                            "label": {
                                                "type": "string",
                                                "description": "Description of the attack vector or goal",
                                            },
                                            "children": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {
                                                            "type": "string",
                                                            "description": "Simple alphanumeric identifier for the leaf node",
                                                        },
                                                        "label": {
                                                            "type": "string",
                                                            "description": "Description of the attack vector or goal",
                                                        },
                                                        "children": {
                                                            "type": "array",
                                                            "items": {},
                                                            "default": [],
                                                        },
                                                    },
                                                    "required": ["id", "label", "children"],
                                                    "additionalProperties": False,
                                                },
                                            },
                                        },
                                        "required": ["id", "label", "children"],
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "required": ["id", "label", "children"],
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }
