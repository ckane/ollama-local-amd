import requests
from pprint import pprint

# Model to use for code completion (not all models support code completion)
model = "deepseek-coder-v2:latest"

# Model-specific keywords for code completion use cases
# Note that sometimes (deepseek-coder-v2 is an example) these contain extended UTF characters
fim_begin  = "<｜fim▁begin｜>"
fim_cursor = "<｜fim▁hole｜>"
fim_end    = "<｜fim▁end｜>"

# Build a JSON prompt to send to the deepseek-r1:7b LLM
data = {
    "model": model,
    # Example prompt pulled from https://huggingface.co/deepseek-ai/DeepSeek-Coder-V2-Instruct#code-insertion
    "prompt": f"""{fim_begin}def quick_sort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[0]
    left = []
    right = []
{fim_cursor}
        if arr[i] < pivot:
            left.append(arr[i])
        else:
            right.append(arr[i])
    return quick_sort(left) + [pivot] + quick_sort(right){fim_end}""",
    "stream": False,

    # Set raw=True to get raw output without any additional formatting or processing
    "raw": True,
}

# POST the prompt to ollama
r = requests.post("http://localhost:11434/api/generate", json=data)

try:
    # Display the original prompt
    print("Prompt:")
    print(data["prompt"])

    # Display the Response from the AI (should only be the completion to insert where fim_cursor is)
    print("\nResponse:")
    print(r.json()['response'])
except Exception as e:
    # In the event of an exception, dump the associated error information
    pprint(e)
    pprint(f"Error: {r.status_code} - {r.text}")
