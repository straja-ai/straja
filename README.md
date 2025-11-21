# Straja Gateway

🚀 **Straja** is a local, OpenAI‑compatible AI gateway that filters, routes, and activates LLM traffic inside your infrastructure.

It provides:
- Security (PII filtering, jailbreak prevention)
- Privacy (no upstream keys in apps)
- Observability (activation events)
- Provider routing (OpenAI, Azure, local models)
- Drop‑in DX: only change the base URL + API key

---

# 📦 Installation

Straja is distributed as a single binary (Linux, macOS) and official Docker images.

### Download (example)

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

# ⚙️ Configuration (`straja.yaml`)

```yaml
server:
  addr: ":8080"

default_provider: "openai_default"

providers:
  openai_default:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"

projects:
  - id: "customer-chat-prod"
    provider: "openai_default"
    api_keys:
      - "proj-chat-key-123"
```

---

# 🚀 Integration (Drop‑in)

Replace this:

```ts
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: "https://api.openai.com/v1",
});
```

With this:

```ts
const client = new OpenAI({
  apiKey: process.env.STRAJA_API_KEY,        // Straja project key
  baseURL: "https://straja.internal/v1",
});
```

Nothing else changes—same models, same SDKs, same request shape.

---

# 🔐 Key Model

### Application key (per project)
- `"proj-chat-key-123"`
- Identifies the caller to Straja
- Defines which provider + policy apply

### Provider key (private inside Straja)
- Stored as env var
- Used for upstream calls
- Never exposed to applications

---

# 🔄 Request Flow

```
Application
  → Authorization: Bearer <project_key>
  → Straja Gateway
    → Policy check (before model)
    → Provider routing
    → Upstream LLM
    ← Straja
      → Policy check (after model)
      → Activation event
    ← Application
```

---

# 🛡️ Policies (before/after model)

Straja runs policies in two stages:

1. **BeforeModel**  
   - PII detection  
   - Prompt injection  
   - Toxicity triggers  
   - Custom regex

2. **AfterModel**  
   - Output filtering  
   - Jailbreak detection  
   - Automated redaction  
   - Safety scoring

Policies run on every project unless customized.

---

# 🔥 Activation Events

Every request produces a structured JSON activation event that can go to:

- stdout
- file
- webhook
- Kafka
- OpenTelemetry

Each event includes:

- project_id  
- provider  
- model  
- risk scores  
- final decision: allow / block / redact

---

# 🧱 Directory Structure

```
straja/
  cmd/straja/        → CLI entrypoint
  internal/
    server/          → HTTP server
    provider/        → Upstream providers
    policy/          → Policy engine
    inference/       → Internal request model
    auth/            → Project → key mapping
    config/          → YAML config loader
```

---

# 🧪 Local Testing

### Run:

```bash
go run ./cmd/straja
```

### Request:

```bash
curl -X POST http://localhost:8080/v1/chat/completions   -H "Content-Type: application/json"   -H "Authorization: Bearer proj-chat-key-123"   -d '{
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Hello from Straja"}]
  }'
```

---

# 🗺 Future Roadmap (High-Level)

- Multiple providers per project
- Streaming support
- Local ONNX / WebGPU inference
- Built‑in classifiers (PII, prompt injection)
- Signed intelligence bundles
- Activation dashboard
- License‑key validation

---

# 📝 License

MIT

---

# 💬 Contact

hello@straja.ai
**https://straja.ai**
