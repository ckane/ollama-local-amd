#!/usr/bin/env python
import chromadb
import requests
from pprint import pprint
from hashlib import sha256

from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_chroma.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings

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
# use 2 of them, but in production more would be better.
r_docs = chroma.similarity_search(code, k=2)

# Iterate across each result from Chroma
for doc in r_docs:
    # Display which source file it came from (using the schema created in load_chroma.py)
    print('#  ' + doc.metadata['source'] + ':')

    # Display the embedding snippet content
    print(doc.page_content)
