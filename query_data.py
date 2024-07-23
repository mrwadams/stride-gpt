import argparse
from langchain.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from db_ops import reload_chroma_db
from get_embedding_function import get_embedding_function
from langchain_community.vectorstores import Chroma
import time
import os
load_dotenv()

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

PROMPT_TEMPLATE = """
Bolt is a large language model trained by Adversys.

Bolt is designed to be able to assist with a wide range of tasks, from answering simple questions to providing in-depth explanations and discussions on a wide range of topics. As a language model, Bolt is able to generate human-like text based on the input it receives, allowing it to engage in natural-sounding conversations and provide responses that are coherent and relevant to the topic at hand.

Bolt is constantly learning and improving, and its capabilities are constantly evolving. It is able to process and understand large amounts of text, and can use this knowledge to provide accurate and informative responses to a wide range of questions. Additionally, Bolt is able to generate its own text based on the input it receives, allowing it to engage in discussions and provide explanations and descriptions on a wide range of topics.

Overall, Bolt is a powerful tool that can help with a wide range of tasks and provide valuable insights and information on a wide range of topics. Whether you need help with a specific question or just want to have a conversation about a particular topic, Bolt is here to assist.

Previous conversation history:
{chat_history}

the user will typically ask Bolt a specific question.

Answer the question based only on the following context if appropriate:

{context}

---

Answer the question based on the above context: {question}

If you do not have any context or context relevant to the question they are asking you inform the user that you do not have adequate context to answer this question
"""
def setup_chroma_db():
    embedding_function = get_embedding_function()
    chroma_db = Chroma(persist_directory="chroma", embedding_function=embedding_function)
    return chroma_db

def query_rag(query_text: str, chat_history: str, fetch_context: bool, chroma_db, route: str):
    try:
        print("Querying RAG")
        print("openai key: ", OPENAI_API_KEY)
        model = ChatOpenAI(model="gpt-4o-mini")

        if fetch_context:
            chroma_db = setup_chroma_db()
            # If context is required, proceed with fetching context from the DB
            results = chroma_db.similarity_search_with_score(query_text, k=5)
            context_text = "\n\n---\n\n".join([doc.page_content for doc, _score in results])
            
            # Print the context for debugging
            print("Context being added to the prompt:")
            print(context_text)
        else:
            # No context needed
            context_text = ""

        prompt_template = ChatPromptTemplate.from_template(PROMPT_TEMPLATE)
        prompt = prompt_template.format(context=context_text, question=query_text, chat_history=chat_history)

        response_text = model.invoke(prompt)

        if fetch_context:
            sources = [doc.metadata.get("id", None) for doc, _score in results]
            formatted_response = f"Response: {response_text}\nSources: {sources}"
        else:
            formatted_response = f"Response: {response_text}\nSources: None"

        print(formatted_response)
        return response_text
    
    except ValueError as e:
        print(f"An error occurred: {e}")
        if 'AccessDeniedException' in str(e):
            print("Access denied. Please check your credentials and model permissions.")
        else:
            print("An unexpected error occurred.")
    
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("query", type=str, help="Query string")
    args = parser.parse_args()

    query_rag(args.query, "", fetch_context=True, chroma_db=reload_chroma_db())
