"""STRIDE-GPT: AI-powered threat modeling using the STRIDE methodology."""

import logging

# Silence litellm's import-time warnings about optional AWS deps (botocore).
# These fire on first `import litellm` regardless of whether the user has
# selected a Bedrock/SageMaker provider, and are confusing on a fresh install.
# Must run before any submodule imports litellm.
logging.getLogger("LiteLLM").setLevel(logging.ERROR)
