# Sift MCP — SIFT VM edition 💽

An [MCP](https://modelcontextprotocol.io) server that exposes the **SANS SIFT**
digital-forensics toolkit as tools an LLM can call. Drive it from **Claude
Desktop**, **Ollama Desktop**, or any MCP client.

This edition runs **directly on a SANS SIFT install** (Ubuntu 24.04), reusing the
forensic tools already in the VM. If you'd rather not run a VM, see the
containerized edition (separate repo): **sift-mcp-docker**.

It wraps standard DFIR command-line programs (The Sleuth Kit, Volatility 3,
Plaso, exiftool, YARA, etc.) behind a safe, allowlisted interface. This is a
defensive / investigative tool — it does not generate exploits or malware.

## Contents

```
sift-mcp-vm/
├── server.py            # the MCP server
├── requirements.txt     # Python dependencies
├── install.sh           # venv + deps + toolchain check + optional service
├── sift-mcp.service     # standalone systemd unit (optional manual install)
├── clients/             # example client configs (Claude Desktop, Ollama)
└── README.md
```

## Setup

1. Boot the SIFT VM from the SANS SIFT `.ova`.
2. Clone this repo into the VM:

   ```bash
   git clone <your-repo-url> sift-mcp-vm
   cd sift-mcp-vm
   ```

3. Run the installer:

   ```bash
   chmod +x install.sh
   ./install.sh
   ```

   It creates a virtualenv at the repo root, installs `mcp` + `pydantic` (plus
   Volatility 3 and python-evtx), reports which forensic tools are present, and
   optionally installs a `systemd` service that starts the server on boot.
   Missing binaries simply disable their corresponding MCP tool.

4. Put evidence under `/cases` (e.g. `/cases/case01/disk.E01`).

The endpoint is `http://<vm-ip>:8000/mcp`. Find the VM IP with `ip -4 addr`.

## Running manually (without the service)

```bash
source .venv/bin/activate
SIFT_EVIDENCE_ROOT=/cases SIFT_OUTPUT_ROOT=/cases/output \
  SIFT_HOST=0.0.0.0 SIFT_PORT=8000 python server.py
```

## Installing the systemd service by hand

Edit `sift-mcp.service` so `User=` and the two paths in `ExecStart=` match your
VM (the venv and `server.py` are at the repo root), then:

```bash
sudo cp sift-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sift-mcp.service
systemctl status sift-mcp
```

## The tools

**Disk / file analysis** — `sift_disk_partitions` (mmls), `sift_image_info`
(img_stat), `sift_filesystem_info` (fsstat), `sift_list_files` (fls),
`sift_extract_file` (icat, returns SHA-256), `sift_carve_files` (foremost),
`sift_file_type` (file), `sift_hash_file` (md5/sha1/sha256).

**Memory forensics** — `sift_volatility` (any Volatility 3 plugin).

**Timeline & artifacts** — `sift_create_timeline` (log2timeline),
`sift_export_timeline` (psort), `sift_parse_evtx`.

**Metadata & strings** — `sift_exiftool`, `sift_strings`, `sift_binwalk`,
`sift_hexdump`, `sift_yara_scan`.

**Housekeeping** — `sift_list_evidence`, `sift_server_info` (shows which
binaries are installed).

## Connecting clients

Both configs are in `clients/`. Use `http://<vm-ip>:8000/mcp` as the URL.

### Claude Desktop

Claude Desktop speaks MCP over stdio, so bridge to the HTTP endpoint with
`mcp-remote` (needs Node.js on the host). Edit
`%APPDATA%\Claude\claude_desktop_config.json` (Windows) or
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "sift": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://<vm-ip>:8000/mcp", "--transport", "http-only"]
    }
  }
}
```

### Ollama Desktop

Use [`mcphost`](https://github.com/mark3labs/mcphost) to bridge an Ollama model
to MCP:

```bash
go install github.com/mark3labs/mcphost@latest
mcphost -m ollama:qwen2.5 --config clients/ollama_mcphost_config.example.json
```

Set the `url` in that config to `http://<vm-ip>:8000/mcp`. Use a tool-calling
model (e.g. `qwen2.5`, `llama3.1`).

### Quick check

```bash
curl -i http://<vm-ip>:8000/mcp
```

A `406 Not Acceptable` is expected and good — it means the server is up (it only
accepts proper MCP POSTs, not bare GETs). A connection error means it's not
reachable; check the VM firewall (`sudo ufw allow 8000/tcp`) and networking.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `SIFT_EVIDENCE_ROOT` | `/cases` | Read-only root for evidence files |
| `SIFT_OUTPUT_ROOT` | `/cases/output` | Where tools may write results |
| `SIFT_HOST` | `0.0.0.0` | Bind address |
| `SIFT_PORT` | `8000` | Bind port |
| `SIFT_TIMEOUT` | `600` | Default per-command timeout (s) |
| `SIFT_MAX_OUTPUT_CHARS` | `60000` | Output truncation limit |
| `SIFT_TRANSPORT` | `streamable-http` | Set `stdio` to run locally without HTTP |

## Security model

- Each tool runs one fixed, allowlisted binary via `exec` — never a shell.
- File paths are resolved (symlinks included) and confined to the evidence root
  (read) and output root (write); anything outside is rejected.
- Plugin names, carve types, inode addresses, and parser names are
  shape-validated. Every command runs under a timeout with truncated output.
- The server has **no authentication** — keep the endpoint on a trusted/private
  network, never the public internet.
