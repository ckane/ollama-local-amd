#!/usr/bin/env python
import chromadb
import requests
from pprint import pprint
from hashlib import sha256

from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_chroma.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings

# Model to use for code completion (not all models support code completion)
model = "qwen2.5-coder:7b"

# Model-specific keywords for code completion use cases
# Note that sometimes (deepseek-coder-v2 is an example) these contain extended UTF characters
fim_begin  = "<|fim_prefix|>"
fim_cursor = "<|fim_suffix|>"
fim_end    = "<|fim_middle|>"
file_sep   = "<|file_sep|>"

# Open a connection to the ChromaDB server
client = chromadb.HttpClient(host='localhost', port='3001')

# Connect to the same embedding model that was used to create the
# embeddings in load_chroma.py
embed = OllamaEmbeddings(
    model='nomic-embed-text:latest',
    base_url='http://localhost:11434',
)

# Open a session to query the py_collection_test collection within Chroma
# this was populated by load_chroma.py
chroma = Chroma(
    collection_name='py_collection_test',
    client=client,
    embedding_function=embed,
)

# An example snippet of Python code that we would like to use to query
# chroma for similarity
code = """from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
functions = fm.get"""


# Perform the similarity search against the chroma database. The k= param
# will control the number of "top results" to return. For this example, we'll
# grab 5 of them.
r_docs = chroma.similarity_search(code, k=5)

# First, an example of building the query without including the context from ChromaDB
data_norag = {
    "model": model,
    "prompt": f"{fim_begin}{code}{fim_cursor}{fim_end}",
    "stream": False,
    "raw": True,
}

# Then, use the ChromaDB query response as part of the input prompt to the coder LLM
data_rag = {
    "model": model,
    "prompt": "{fim_begin}{file_sep}\n{context}\n{file_sep}{code}{fim_cursor}{fim_end}".format(
        fim_begin=fim_begin, file_sep=file_sep, fim_cursor=fim_cursor, fim_end=fim_end,
        context=f"\n{file_sep}".join([doc.page_content for doc in r_docs]),
        code=code,
    ),
    "stream": False,
    "raw": True,
}

data = data_rag

# POST the request to ollama
r = requests.post("http://localhost:11434/api/generate", json=data)

try:
    # Display the prompt, followed by the ollama response
    print("Prompt:" + data["prompt"])
    print("---------------------------------------------------")

    # Denote where the cursor would be using >>> (the Python CLI prompt)
    print("Response: >>>" + r.json()['response'])
except Exception as e:
    # In the event of an exception, show the details that caused it
    pprint(e)
    pprint(f"Error: {r.status_code} - {r.text}")
