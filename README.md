# Straja Gateway

🚀 **Straja** is a local, OpenAI-compatible AI gateway that filters, routes, and activates LLM traffic *inside your infrastructure*.

It provides:
- **Security:** PII filtering, jailbreak detection, prompt-injection protection  
- **Privacy:** LLM provider keys stay inside Straja  
- **Observability:** structured activation events  
- **Provider routing:** OpenAI, Azure, local inference  
- **Drop-in DX:** same OpenAI API, same SDKs  

---

# 📦 Installation

Straja is distributed as:
- a single binary (Linux, macOS)
- official Docker images

### Binary installation

```bash
curl -LO https://github.com/straja-ai/straja/releases/latest/download/straja
chmod +x straja
./straja --config straja.yaml
```

### Docker

```bash
docker run -p 8080:8080   -v $(pwd)/straja.yaml:/straja.yaml   -e OPENAI_API_KEY=your-real-openai-key   somanole/straja:latest
```

---

# 🔐 Provider API Keys (`.env` support)

Straja loads upstream API keys from a local `.env` file.

### Create `.env`

```
OPENAI_API_KEY=sk-123...
AZURE_OPENAI_KEY=xyz...
```

### Ensure `.env` is ignored by Git

```
# .gitignore
.env
*.env
.env.*
```

### Makefile auto-loads `.env`

You can run Straja locally without exporting any keys globally:

```bash
make run
```

Equivalent to:

```
env $(cat .env | xargs) go run ./cmd/straja --config=straja.yaml
```

---

# ⚙️ Configuration (`straja.yaml`)

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"  # Loaded from .env

projects:
  - id: "customer-chat-prod"
    provider: "openai_default"
    api_keys:
      - "proj-chat-key-123"
```

📝 **Application code never sees provider secrets** — Straja injects them internally.

---

# 🔑 Key Model

### Application / project key  
Sent by applications calling Straja:

```
Authorization: Bearer proj-chat-key-123
```

### Provider key (in `.env`)  
Used internally by Straja to call upstream LLMs.

---

# 🧪 Quick Start (5 minutes)

### 1. Clone the repo

```bash
git clone https://github.com/straja-ai/straja.git
cd straja
```

### 2. Create `.env`

```
OPENAI_API_KEY=your-real-openai-key
```

### 3. Create `straja.yaml`

```yaml
server:
  addr: ":8080"
default_provider: "openai"
providers:
  openai:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"
projects:
  - id: "local-test"
    provider: "openai"
    api_keys: ["test-key"]
```

### 4. Run Straja

```bash
make run
```

### 5. Send your first request

```bash
curl -X POST http://localhost:8080/v1/chat/completions   -H "Content-Type: application/json"   -H "Authorization: Bearer test-key"   -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello Straja"}]
  }'
```

🎉 You now have a working AI gateway.

---

# 🚀 Drop-in Integration

Replace your OpenAI client:

```ts
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: "https://api.openai.com/v1",
});
```

With Straja:

```ts
const client = new OpenAI({
  apiKey: process.env.STRAJA_API_KEY, 
  baseURL: "http://localhost:8080/v1",
});
```

Everything else stays the same.

---

# 🔄 Request Lifecycle

```
Application
  → Straja (BeforeModel policy)
    → Provider routing
    → Upstream LLM
  ← Straja (AfterModel policy)
  ← Activation event logged
```

Decisions include:

- `allow`
- `blocked_before_policy`
- `blocked_after_policy`
- `redacted`

---

# 🛡️ Policies

### BeforeModel
- PII detection (email, phone, CC, IBAN, tokens)
- Banned words
- SQL/command injection
- Prompt injection
- Jailbreak patterns
- Toxicity

### AfterModel
- Output redaction
- Sensitive token masking
- Completion sanitization

---

# 🔥 Activation Events

Sent for every request via:
- stdout  
- file  
- webhook  
- Kafka  
- OTEL (coming soon)

Event includes:

```json
{
  "timestamp": "...",
  "project_id": "local-test",
  "provider": "openai",
  "model": "gpt-4.1-mini",
  "decision": "allow",
  "policy_hits": ["pii"],
  "prompt_preview": "Hello...",
  "completion_preview": "Hi there..."
}
```

---

# 🧱 Repository Structure

```
straja/
  cmd/straja/          → CLI entrypoint
  internal/
    server/            → HTTP server + routing
    provider/          → OpenAI, Azure, others
    policy/            → Safety filters
    activation/        → Activation event sinks
    inference/         → Internal request shapes
    auth/              → Project-key authentication
    config/            → YAML + env loader
  console/             → HTML developer console
```

---

# 🧪 Development

### Test

```bash
make test
```

### Format

```bash
make fmt
```

### Lint

```bash
make lint
```

### Build binary

```bash
make build
```

---

# 🗺 Roadmap

- Streaming support  
- Local ONNX inference  
- Multi-provider orchestration  
- Signed intelligence bundles  
- Enterprise policy packs  
- Activation dashboard  
- License key system  

---

# 📝 License

MIT

---

# 💬 Contact

hello@straja.ai  
https://straja.ai
