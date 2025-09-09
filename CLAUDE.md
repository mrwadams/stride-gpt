# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

STRIDE GPT is an AI-powered threat modeling tool built with Streamlit that generates threat models and attack trees using the STRIDE methodology. The application supports multiple LLM providers (OpenAI, Anthropic, Google, Mistral, Ollama, LM Studio, Groq) and can analyze applications based on user input or GitHub repository analysis.

## Commands

### Running the Application
```bash
# Install dependencies
pip install -r requirements.txt

# Run the Streamlit app locally
streamlit run main.py

# Using Docker
docker pull mrwadams/stridegpt:latest
docker run -p 8501:8501 --env-file .env mrwadams/stridegpt
```

### Testing
```bash
# No formal test framework configured - manual testing via Streamlit UI
# Test cases are defined in test_cases.py but are output generation, not unit tests
```

### Environment Setup
```bash
# Copy environment template and configure API keys
cp .env.example .env
# Edit .env file with your API keys for various LLM providers
```

## Architecture

### Core Modules
- **main.py**: Primary Streamlit application entry point and UI orchestration
- **threat_model.py**: Threat model generation logic with multi-provider LLM support
- **attack_tree.py**: Attack tree generation with Mermaid diagram visualization
- **mitigations.py**: Mitigation suggestion generation for identified threats
- **dread.py**: DREAD risk scoring assessment functionality
- **test_cases.py**: Gherkin test case generation from threat models
- **utils.py**: Shared utilities including response processing and reasoning extraction

### Multi-Provider Architecture
Each core module (threat_model, attack_tree, mitigations, dread, test_cases) implements functions for all supported LLM providers:
- OpenAI API (`get_*`)
- Azure OpenAI (`get_*_azure`)
- Google AI/Gemini (`get_*_google`)
- Anthropic (`get_*_anthropic`)
- Mistral API (`get_*_mistral`)
- Ollama local models (`get_*_ollama`)
- LM Studio Server (`get_*_lm_studio`)
- Groq API (`get_*_groq`)

### Key Features
- **Multi-modal support**: Image analysis for architecture diagrams (supported by vision-capable models)
- **GitHub integration**: Automatic repository analysis using PyGithub
- **Reasoning model support**: Handles OpenAI's reasoning models (o1, o3 series) and DeepSeek R1
- **Local model support**: Integration with Ollama and LM Studio for on-premises deployment
- **Export functionality**: Downloadable Markdown outputs for all generated content

### Data Flow
1. User provides application details via Streamlit UI or GitHub URL
2. Application details are processed into structured prompts
3. Selected LLM provider generates threat model in JSON format
4. JSON is converted to Markdown for display
5. Additional analyses (attack trees, mitigations, DREAD, test cases) can be generated from the threat model
6. All outputs are available for download as Markdown files

### Configuration
- API keys loaded from `.env` file or environment variables
- Model selection and parameters handled through Streamlit interface
- Docker deployment supported with environment variable injection
- No persistent data storage - all data is session-based