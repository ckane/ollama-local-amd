import requests
from pprint import pprint

model = "deepseek-r1:7b"

# Build a JSON prompt to send to the deepseek-r1:7b LLM
data = {
    "model": model,
    "prompt": "Hello how are you?",
    "stream": False,
}

# POST the prompt to ollama
r = requests.post("http://localhost:11434/api/generate", json=data)

try:
    # Display the original prompt
    print("Prompt:")
    print(data["prompt"])

    # Display the Response from the AI
    print("\nResponse:")
    print(r.json()['response'])
except Exception as e:
    # In the event of an exception, dump the associated error information
    pprint(e)
    pprint(f"Error: {r.status_code} - {r.text}")
