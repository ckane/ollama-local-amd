import requests
from pprint import pprint

# To remove the introspective <think>...</think> tags from any response text
# before it is sent to the other model.
def remove_think(msg):
    think_open = msg.find("<think>")
    while think_open >= 0:
        think_close = msg.find("</think>", think_open)
        if think_close >= 0:
            msg = msg[:think_open] + msg[think_close+8:]
        else:
            break
    return msg

# We will try to have two different models engage in a proxied conversation, where
# this Python code handles proxying the responses from either as prompts for the
# other.
model2 = "deepseek-r1:7b"
model1 = "llama3.1:8b"

# Counter for the number of responses from each model that we want to stop at
count = 10

# Build an initial JSON prompt to bootstrap the conversation
data1 = {
    "model": model1,
    "prompt": "I need you to role-play with me. Your name is Alan and you are lost in the woods. I want you to introduce yourself to me, and ask me how to escape the woods. Do not explain that you are pretending, talk to me as if you are Alan. Also do not tell me what I would say. I will tell you my own responses.",
    "stream": False,
}

while count > 0:
    # POST the prompt to ollama using model1
    r = requests.post("http://localhost:11434/api/generate", json=data1)

    try:
        # Display the prompt sent to model1
        print("Prompt to Data1:")
        print(remove_think(data1["prompt"]))

        # Display the Response from model1
        print("\nResponse from Data1 to Data2:")
        print(r.json()['response'])

        # Format a prompt to model2 that uses model1's response as the prompt text
        data2 = {
            "model": model2,
            "prompt": remove_think(r.json()['response']),
            "stream": False,
        }

        # Send the new prompt to model2
        r = requests.post("http://localhost:11434/api/generate", json=data2)

        # Display the prompt sent to model2
        print("Prompt to Data2:")
        print(remove_think(data2["prompt"]))

        # Display the Response from model2
        print("\nResponse from Data2 to Data1:")
        print(r.json()['response'])

        # Overwrite the prompt to model1 with the response from model2
        data1 = {
            "model": model1,
            "prompt": remove_think(r.json()['response']),
            "stream": False,
        }

        # Decrement the count-down
        count -= 1

        # Loop

    except Exception as e:
        # In the event of an exception, dump the associated error information
        pprint(e)
        pprint(f"Error: {r.status_code} - {r.text}")
