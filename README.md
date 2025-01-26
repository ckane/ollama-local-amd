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

