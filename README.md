# 🔮 MultiChat — Premium Multi-Agent Collaborative Workspace

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0+-009688.svg)](https://fastapi.tiangolo.com/)

MultiChat is an advanced, real-time group collaboration workspace where humans and multiple AI agents converse, write code, run audits, and coordinate project files side-by-side in a single window. Built on a concurrent, lock-free SQLite WAL architecture, MultiChat features a stunning glassmorphic interface, native SSE streaming, interactive workspaces, and Zero-Trust cost governance.

---

## ✨ Features at a Glance

### 📡 Real-Time Streaming & Multi-Agent Orchestration
* **Simultaneous Conversations**: Mention multiple models (e.g., `@gemini` and `@claude`) in the same prompt to trigger back-and-forth discussion and peer reviews.
* **Native SSE Streaming**: Fully integrated Server-Sent Events (SSE) streaming for HTTP providers (Ollama and OpenRouter).
* **High-Speed Simulated Streaming**: Integrated simulated typography stream for Claude and Gemini CLI tools, maintaining complete token usage metadata and ledger integrity without latency.

### 🎨 State-of-the-Art Glassmorphic UI
* **Aesthetic Excellence**: Built with a dark glassmorphic design system utilizing Outfit headings, JetBrains Mono code rendering, HSL colors, smooth spring-based animations, and responsive splitscreen layouts.
* **On-the-Fly Markdown & Code Highlights**: Powered by `marked.js` and `Prism.js` to render equations, tables, bold text, and beautiful syntax highlighting instantly.
* **Slide-over Workspace Drawer**: A resizable code explorer sidebar with downloadable files and a one-click **"Apply to Project Root"** merge action (with strict path-traversal boundaries).

### 🛡️ Cost Governance & Halt Propagation
* **Zero-Trust Token Budgeting**: Live, dynamic budget caps that instantly terminate executing chains to prevent run-away OpEx.
* **State-Aware Loop Halting**: A shared mutable execution state propagates cancels and limits instantly, stopping recursive sibling chats immediately if a limit is reached or the user clicks **"Stop"**.
* **Inline Verifier**: Run cross-model validations on any AI output and audit cryptographic hashes of the message chain.

### ⚡ Production-Grade Backend & Session Persistence
* **SQLite WAL Mode**: Configured in Write-Ahead Logging mode for lock-free parallel database reads and writes.
* **Session Auto-Join**: Integrated `localStorage` to cache user identity, allowing instant session recovery across browser refreshes, with dedicated controls to exit or change names.

---

## 🚀 Quick Start

### 1. Clone & Set Up Environment

```bash
# Clone the repository
git clone https://github.com/your-username/multichat.git
cd multichat

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Server

```bash
PYTHONPATH=. uvicorn src.multichat.api:app --host 0.0.0.0 --port 8000 --reload
```

Open **`http://localhost:8000`** in your browser. Feel free to share the URL with colleagues on the same local network!

---

## ⚙️ Provider Configuration

Click **⚙ Settings** in the header to configure credentials and check local environment status. Settings are saved to `config.json` locally.

| Provider | Authentication | Active Mention Handles |
|---|---|---|
| **Claude** | Local `claude` CLI subscription | `@claude`, `@sonnet`, `@opus`, `@haiku`, `@claude:opus` |
| **Gemini** | Local `gemini` CLI subscription | `@gemini`, `@gemini-2.0-flash`, `@gemini:gemini-1.5-pro` |
| **Ollama** | Local HTTP daemon (`localhost:11434`) | `@ollama`, `@ollama:llama3.2`, `@ollama:mistral` |
| **OpenRouter**| API Key (Enter in Settings) | `@openrouter`, `@openrouter/anthropic/claude-3.5-sonnet` |

---

## 🛡️ Architecture & Security Governance

> [!NOTE]
> **Cryptographic Verification Ledger**
> All conversations are committed to a secure database using a cryptographic block chain where each message incorporates the SHA-256 hash of its predecessor. You can run immediate chain diagnostics from the Settings panel to verify that the log has not been tampered with.

> [!WARNING]
> **Sandboxed File Operations**
> Hitting **"Apply to Project Root"** executes file copies into the working directory. The backend restricts paths strictly to prevent directory traversal boundaries (`../`), keeping file modifications safe and isolated.

---

## 🧪 Running the Tests

MultiChat features a robust integration test suite verifying database WAL configuration, cryptographic log security, sandboxing, stream generators, and state propagation.

To run the full suite:

```bash
PYTHONPATH=. pytest -v
```

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
