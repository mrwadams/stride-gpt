
import os
from langchain_community.embeddings import OpenAIEmbeddings
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

def get_embedding_function():
    embedding_function = OpenAIEmbeddings(
        openai_api_key=OPENAI_API_KEY,
        model="text-embedding-3-small"
    )
    return embedding_function
