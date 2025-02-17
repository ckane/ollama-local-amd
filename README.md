# README

As the repository title suggests, this is a very simple `docker compose` template that I have been using
to host [Ollama](https://ollama.com/) and [Open-WebUI](https://github.com/open-webui/open-webui) on my
local Linux workstation, with support for [AMDGPU ROCm](https://rocm.docs.amd.com/projects/install-on-linux/en/latest/)
acceleration.

# Running

After cloning the repository, it should work simply by running the following command in the folder:
```sh
docker compose up --wait
```

# Using

API access via: `http://localhost:11434`

GUI access via: `http://localhost:3000`

![Screenshot of Open WebUI with DeepSeek-R1 Chat](/img/screenshot.png)

You will need to manually pull down models you wish to use via the WebUI, or via the CLI. On the CLI, this can
be accomplished via:
```sh
docker compose exec ollama ollama pull {modelname}
```

Where `{modelname}` is the model name in the [Ollama model library](https://ollama.ai/library).

# Configuration

## Vim Integration

I use the following Vim plugin: [vim-ollama](https://github.com/gergap/vim-ollama)

The following is used to set it up with DeepSeek, but also the defaults are to use the llama3 stuff:
```vim
let g:ollama_chat_model = 'deepseek-r1:latest'
let g:ollama_model = 'deepseek-coder-v2:latest'
```


Disable copilot if you have it installed and you don't want the two plugins conflicting:
```vim
let g:copilot_enabled = 0
```
