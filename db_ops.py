import os
from langchain_community.vectorstores import Chroma
from get_embedding_function import get_embedding_function
import argparse
import shutil
import time
import psutil
from langchain_community.document_loaders.pdf import PyPDFDirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from collections import Counter
import matplotlib.pyplot as plt
import time
# import excel loader
from langchain_community.document_loaders.csv_loader import CSVLoader
from typing import List, Dict

PDF_DATA_PATH = './data/pdf'
CSV_DATA_PATH = './data/csv'
CHROMA_PATH = "chroma"

import os
import shutil

def add_data(file):
    data_dir = "data"
    pdf_dir = os.path.join(data_dir, "pdf")
    csv_dir = os.path.join(data_dir, "csv")

    # Print current working directory
    current_working_directory = os.getcwd()
    print(f"Current working directory: {current_working_directory}")

    # Create directories if they don't exist
    for directory in [pdf_dir, csv_dir]:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Created directory {directory}")
            except Exception as e:
                print(f"Failed to create directory {directory}: {e}")
                return

    # Determine the destination directory based on the file type
    if file.name.endswith(".pdf"):
        print(f"File type: pdf")
        destination_dir = pdf_dir
    elif file.name.endswith(".csv"):
        print(f"File type: csv")
        destination_dir = csv_dir
    else:
        print("Unsupported file type. Only PDF and CSV files are supported.")
        print(f"File type: {file.name.split('.')[-1]}")
        return

    file_path = os.path.join(destination_dir, os.path.basename(file.name))
    print(f"Destination directory: {destination_dir}")
    print(f"File path: {file_path}")

    # Save the uploaded file to the destination directory
    with open(file_path, "wb") as f:
        f.write(file.getbuffer())
    print(f"Saved file {file.name} to {file_path}")

    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist after attempting to save it.")
        return

    populate_database()
    reload_chroma_db()
    print(f"File {file_path} processed successfully.")


def populate_database(reset=False):
    if reset:
        print("✨ Clearing Database")
        clear_database()

    documents = []

    # Load all PDF documents from the directory
    pdf_data_path = './data/pdf'
    print("Loading PDF documents...")
    documents.extend(load_pdf_documents(pdf_data_path))

    # Load individual CSV documents
    csv_data_path = './data/csv'
    for file in os.listdir(csv_data_path):
        file_path = os.path.join(csv_data_path, file)
        if file.endswith(".csv"):
            print(f"Loading CSV document: {file}")
            documents.extend(load_csv_documents(file_path))
        else:
            print(f"Unsupported file type for {file}. Skipping.")

    print(f"Loaded {len(documents)} documents")

    print("Splitting documents into chunks...")
    chunks = split_documents(documents)
    print(f"Split into {len(chunks)} chunks")

    print("Adding chunks to Chroma database...")
    add_to_chroma(chunks)



def load_pdf_documents(directory_path):
    document_loader = PyPDFDirectoryLoader(directory_path)
    return document_loader.load()

def load_csv_documents(file_path):
    loader = CSVLoader(file_path=file_path)
    try:
        return loader.load()
    except PermissionError as e:
        print(f"Permission error while loading CSV file: {e}")
        raise
    except Exception as e:
        print(f"Error loading CSV documents: {e}")
        raise

def split_documents(documents: List[Document]):
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=80,
        length_function=len,
        is_separator_regex=False,
    )
    
    splits = text_splitter.split_documents(documents)
    
    # Collect statistics
    split_lengths = [len(split.page_content) for split in splits]
    stats = {
        'num_splits': len(splits),
        'min_split_length': min(split_lengths),
        'max_split_length': max(split_lengths),
        'avg_split_length': sum(split_lengths) / len(split_lengths),
        'split_length_distribution': Counter(split_lengths),
    }

    # Define save path
    save_path = 'embedding_statistics'
    os.makedirs(save_path, exist_ok=True)

    # Plot split length distribution
    lengths = list(stats['split_length_distribution'].keys())
    counts = list(stats['split_length_distribution'].values())
    
    plt.figure(figsize=(10, 6))
    plt.bar(lengths, counts)
    plt.xlabel('Split Length')
    plt.ylabel('Count')
    plt.title('Split Length Distribution')
    plt.savefig(os.path.join(save_path, 'split_length_distribution.png'))
    plt.close()
    
    # Assuming similarity scores and document segment indices are available
    similarity_scores = [0.5] * len(split_lengths)  # Placeholder values
    document_segment_indices = list(range(len(split_lengths)))  # Placeholder values
    
    plt.figure(figsize=(12, 8))
    
    # Plot similarity scores vs. document segment index
    plt.subplot(2, 1, 1)
    plt.plot(document_segment_indices, similarity_scores, marker='o', linestyle='-', label='Similarity Scores')
    plt.axhline(y=0.226, color='g', linestyle='-', label='Threshold Similarity Score')  # Example threshold
    for i in range(len(similarity_scores)):
        plt.axvline(x=i, color='r', linestyle='--')
    plt.xlabel('Document Segment Index')
    plt.ylabel('Similarity Score')
    plt.title('Similarity Scores vs. Document Segment Index')
    plt.legend()
    
    # Plot split token sizes
    plt.subplot(2, 1, 2)
    plt.bar(range(len(split_lengths)), split_lengths)
    plt.xlabel('Split Index')
    plt.ylabel('Token Count')
    plt.title('Split Token Sizes')
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_path, 'similarity_scores_and_split_token_sizes.png'))
    plt.close()
    
    # Save statistics to a file
    with open(os.path.join(save_path, 'statistics.txt'), 'w') as f:
        for key, value in stats.items():
            f.write(f"{key}: {value}\n")

    return splits

def add_to_chroma(chunks: list[Document]):
    # Load the existing database.
    db = Chroma(
        persist_directory=CHROMA_PATH, embedding_function=get_embedding_function()
    )

    # Calculate Page IDs.
    chunks_with_ids = calculate_chunk_ids(chunks)

    # Add or Update the documents.
    existing_items = db.get(include=[])  # IDs are always included by default
    existing_ids = set(existing_items["ids"])
    print(f"Number of existing documents in DB: {len(existing_ids)}")

    # Only add documents that don't exist in the DB.
    new_chunks = []
    for chunk in chunks_with_ids:
        if chunk.metadata["id"] not in existing_ids:
            new_chunks.append(chunk)

    if len(new_chunks):
        print(f"👉 Adding new documents: {len(new_chunks)}")
        new_chunk_ids = [chunk.metadata["id"] for chunk in new_chunks]
        db.add_documents(new_chunks, ids=new_chunk_ids)
        db.persist()
    else:
        print("✅ No new documents to add")

def calculate_chunk_ids(chunks):
    # This will create IDs like "data/monopoly.pdf:6:2"
    # Page Source : Page Number : Chunk Index

    last_page_id = None
    current_chunk_index = 0

    for chunk in chunks:
        source = chunk.metadata.get("source")
        page = chunk.metadata.get("page")
        current_page_id = f"{source}:{page}"

        # If the page ID is the same as the last one, increment the index.
        if current_page_id == last_page_id:
            current_chunk_index += 1
        else:
            current_chunk_index = 0

        # Calculate the chunk ID.
        chunk_id = f"{current_page_id}:{current_chunk_index}"
        last_page_id = current_page_id

        # Add it to the page meta-data.
        chunk.metadata["id"] = chunk_id

    return chunks

def clear_database():
    if os.path.exists(CHROMA_PATH):
        retry_attempts = 5
        delay = 1  # seconds
        for attempt in range(retry_attempts):
            try:
                shutil.rmtree(CHROMA_PATH)
                print("Database cleared.")
                return
            except PermissionError as e:
                print(f"Attempt {attempt + 1}/{retry_attempts} failed: {e}")
                time.sleep(delay)
                # Close file handles using psutil
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        for handle in proc.open_files():
                            if CHROMA_PATH in handle.path:
                                proc.terminate()
                                proc.wait()
                    except psutil.NoSuchProcess:
                        pass
        print("Failed to clear the database after several attempts.")

def reload_chroma_db():
    embedding_function = get_embedding_function()
    chroma_db = Chroma(persist_directory=CHROMA_PATH, embedding_function=embedding_function)
    num_documents = len(chroma_db.get(include=['documents'])['documents'])
    print(f"Number of documents in Chroma DB after reloading: {num_documents}")
    return chroma_db
