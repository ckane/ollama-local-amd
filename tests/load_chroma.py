#!/usr/bin/env python
import chromadb
from pprint import pprint
from hashlib import sha256
from glob import iglob

# Import LangChain features we will use
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_chroma.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings

# Initialize a connection to ChromaDB to store embeddings
client = chromadb.HttpClient(host='localhost', port='3001')

# Initialize a connection to Ollama to generate embeddings
embed = OllamaEmbeddings(
    model='nomic-embed-text:latest',
    base_url='http://localhost:11434',
)

# Create a new collection (if it doesn't exist already) and open it
chroma = Chroma(
    collection_name='py_collection_test',
    client=client,
    embedding_function=embed,
)

# Start scanning below a Ghidra installation folder
root_dir="../../ghidra_11.1.2_PUBLIC"

# Walk the filesystem below root_dir, and pick all *.py files
myglob = iglob("**/*.py",
               root_dir=root_dir,
               recursive=True)

# Even though the GenericLoader from langchain has a glob-based filesystem
# walking feature, if any of the files cause a parser exception, it will
# pass this exception up to the lazy_load() or load() iterator call, failing
# every subsequent file. Use the Python glob interface to load the files one
# at a time with GenericLoader and LanguageParser, and if any throw an exception,
# discard that one file, and continue on to try the next
for fsentry in myglob:
    try:
        # Try creating a new GenericLoader for the file
        loader = GenericLoader.from_filesystem(
            f"{root_dir}/{fsentry}",
            parser=LanguageParser(language='python'),
            show_progress=False,
        )

        # Try loading the file through its parser
        for doc in loader.lazy_load():
            # Set some useful metadata from the file context
            newdoc = {
                "page_content": doc.page_content,
                "metadata": {
                    "source": doc.metadata["source"],
                    "language": 'python',
                },
            }
            # Generate a SHA256 "unique id" for each embedding, to help dedupe
            h = sha256(newdoc['page_content'].encode('utf-8')).hexdigest()

            # Store the embedding into ChromaDB
            chroma.add_documents(documents=[doc], ids=[h])
    except Exception as e:
        # If the file failed to load and/or parse, then report it to STDOUT
        pprint(f"Failed with {fsentry}!")
        #pprint(e)  # To dump the exception details, if needed
        continue
