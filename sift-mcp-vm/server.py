#!/usr/bin/env python3
"""
sift_mcp - Model Context Protocol server for the SANS SIFT DFIR toolkit.

Exposes common digital-forensics / incident-response command-line tools as MCP
tools so they can be driven from Claude Desktop, Ollama Desktop, or any other
MCP client. Designed to run *inside* the SIFT VM (Ubuntu 24.04) where the
forensic binaries are installed, and to serve over Streamable HTTP so clients on
the host machine can reach it across the VM network.

Tool groups:
  - Disk / file analysis  : The Sleuth Kit (mmls, fsstat, fls, icat, img_stat),
                            foremost (carving), file type ID, hashing
  - Memory forensics      : Volatility 3 (vol)
  - Timeline & artifacts  : Plaso (log2timeline / psort), EVTX parsing
  - Metadata & strings    : exiftool, strings, binwalk, xxd hexdump, YARA

Security model
--------------
Forensic tools read attacker-controlled evidence, so this server is deliberately
conservative:
  * Every tool runs a fixed, allowlisted binary via exec (never a shell).
  * Every file path argument is resolved and confined to EVIDENCE_ROOT (read) or
    SIFT_OUTPUT_ROOT (write). Path traversal outside those roots is rejected.
  * All commands run with a timeout and have their output truncated.
This is an investigative/defensive tool. It does not generate exploits or
malware.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------- #
# Configuration (override via environment variables)
# --------------------------------------------------------------------------- #

# Root directory that holds evidence (disk images, memory dumps, logs, etc.).
# All read paths must resolve inside this directory.
EVIDENCE_ROOT = Path(os.environ.get("SIFT_EVIDENCE_ROOT", "/cases")).resolve()

# Root directory where tools may write output (carved files, timelines, etc.).
SIFT_OUTPUT_ROOT = Path(os.environ.get("SIFT_OUTPUT_ROOT", "/cases/output")).resolve()

# Default wall-clock timeout for a single tool invocation (seconds).
DEFAULT_TIMEOUT = int(os.environ.get("SIFT_TIMEOUT", "600"))

# Maximum characters of stdout returned to the client (truncated beyond this).
MAX_OUTPUT_CHARS = int(os.environ.get("SIFT_MAX_OUTPUT_CHARS", "60000"))

# Network binding for the HTTP transport.
HOST = os.environ.get("SIFT_HOST", "0.0.0.0")
PORT = int(os.environ.get("SIFT_PORT", "8000"))

mcp = FastMCP("sift_mcp", host=HOST, port=PORT)


# --------------------------------------------------------------------------- #
# Shared enums / models
# --------------------------------------------------------------------------- #

class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


# --------------------------------------------------------------------------- #
# Path safety helpers
# --------------------------------------------------------------------------- #

class PathSecurityError(ValueError):
    """Raised when a requested path escapes an allowed root."""


def _ensure_roots() -> None:
    """Create the output root if missing (evidence root is expected to exist)."""
    try:
        SIFT_OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _resolve_under(path_str: str, root: Path, must_exist: bool) -> Path:
    """Resolve ``path_str`` and confirm it is contained within ``root``.

    Relative paths are interpreted relative to ``root``. Symlinks are resolved so
    a symlink inside the root cannot point outside it.
    """
    candidate = Path(path_str)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise PathSecurityError(
            f"Path '{path_str}' resolves to '{resolved}', which is outside the "
            f"allowed root '{root}'. Place the file under that directory and try again."
        )
    if must_exist and not resolved.exists():
        raise PathSecurityError(
            f"Path '{path_str}' does not exist (looked at '{resolved}'). "
            f"List evidence with sift_list_evidence to see available files."
        )
    return resolved


def _evidence_path(path_str: str) -> Path:
    """Resolve an input/evidence path confined to EVIDENCE_ROOT (must exist)."""
    return _resolve_under(path_str, EVIDENCE_ROOT, must_exist=True)


def _output_path(path_str: str, must_exist: bool = False) -> Path:
    """Resolve an output path confined to SIFT_OUTPUT_ROOT (created as needed)."""
    return _resolve_under(path_str, SIFT_OUTPUT_ROOT, must_exist=must_exist)


# --------------------------------------------------------------------------- #
# Subprocess execution helper
# --------------------------------------------------------------------------- #

def _tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


async def _run(
    argv: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[Path] = None,
) -> Tuple[int, str, str]:
    """Execute ``argv`` directly (no shell) and capture output.

    Returns (returncode, stdout, stderr). Raises asyncio.TimeoutError on timeout.
    """
    binary = argv[0]
    if not _tool_available(binary):
        raise FileNotFoundError(
            f"Required tool '{binary}' is not installed or not on PATH inside the "
            f"SIFT VM. Install it (e.g. via apt) and restart the server."
        )

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        raise

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    return proc.returncode, stdout, stderr


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    omitted = len(text) - MAX_OUTPUT_CHARS
    return text[:MAX_OUTPUT_CHARS] + f"\n\n... [truncated {omitted} characters; narrow the query or write to a file]"


def _format_result(
    command: Sequence[str],
    returncode: int,
    stdout: str,
    stderr: str,
    response_format: ResponseFormat,
    note: Optional[str] = None,
) -> str:
    """Render a command result as markdown or JSON."""
    cmd_str = " ".join(shlex.quote(c) for c in command)
    stdout = _truncate(stdout)
    stderr = _truncate(stderr)

    if response_format == ResponseFormat.JSON:
        return json.dumps(
            {
                "command": cmd_str,
                "returncode": returncode,
                "ok": returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "note": note,
            },
            indent=2,
        )

    lines = [f"**Command:** `{cmd_str}`", f"**Exit code:** {returncode}", ""]
    if note:
        lines += [f"> {note}", ""]
    if stdout.strip():
        lines += ["**Output:**", "```", stdout.rstrip(), "```", ""]
    else:
        lines += ["_No standard output._", ""]
    if returncode != 0 and stderr.strip():
        lines += ["**Errors:**", "```", stderr.rstrip(), "```"]
    elif stderr.strip():
        # Many forensic tools log progress to stderr even on success.
        lines += ["**Messages (stderr):**", "```", stderr.rstrip(), "```"]
    return "\n".join(lines)


async def _run_and_format(
    argv: Sequence[str],
    response_format: ResponseFormat,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[Path] = None,
    note: Optional[str] = None,
) -> str:
    """Run a command and format the result, with consistent error handling."""
    try:
        rc, out, err = await _run(argv, timeout=timeout, cwd=cwd)
        return _format_result(argv, rc, out, err, response_format, note=note)
    except FileNotFoundError as e:
        return f"Error: {e}"
    except asyncio.TimeoutError:
        return (
            f"Error: command timed out after {timeout}s: "
            f"`{' '.join(shlex.quote(c) for c in argv)}`. "
            f"Increase the timeout argument or narrow the scope."
        )
    except PathSecurityError as e:
        return f"Error: {e}"
    except Exception as e:  # noqa: BLE001 - surface a clean message to the agent
        return f"Error: unexpected failure ({type(e).__name__}): {e}"


# =========================================================================== #
# Discovery / housekeeping tools
# =========================================================================== #

class ListEvidenceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    subdirectory: Optional[str] = Field(
        default=None,
        description="Optional subdirectory under the evidence root to list (e.g. 'case01').",
    )
    pattern: str = Field(
        default="*",
        description="Glob pattern to match file names (e.g. '*.E01', '*.raw', '*.dd').",
    )
    recursive: bool = Field(default=True, description="Recurse into subdirectories.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")


@mcp.tool(
    name="sift_list_evidence",
    annotations={
        "title": "List evidence files",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def sift_list_evidence(params: ListEvidenceInput) -> str:
    """List evidence files available under the configured evidence root.

    Use this first to discover what disk images, memory dumps, and log files are
    present, and to get the exact paths to pass to other tools.

    Args:
        params (ListEvidenceInput): subdirectory, glob pattern, recursive flag, format.

    Returns:
        str: A list of relative paths with size in bytes, as markdown or JSON.
    """
    try:
        base = _evidence_path(params.subdirectory) if params.subdirectory else EVIDENCE_ROOT
    except PathSecurityError as e:
        return f"Error: {e}"

    if not base.exists():
        return f"Error: evidence root '{base}' does not exist. Set SIFT_EVIDENCE_ROOT or create it."

    globber = base.rglob if params.recursive else base.glob
    entries: List[Dict[str, Any]] = []
    for p in sorted(globber(params.pattern)):
        if p.is_file():
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            entries.append({"path": str(p.relative_to(EVIDENCE_ROOT)), "size_bytes": size})

    if not entries:
        return f"No files matching '{params.pattern}' found under '{base}'."

    if params.response_format == ResponseFormat.JSON:
        return json.dumps({"evidence_root": str(EVIDENCE_ROOT), "count": len(entries), "files": entries}, indent=2)

    lines = [f"# Evidence under `{EVIDENCE_ROOT}`", f"{len(entries)} file(s)", ""]
    for e in entries:
        mb = e["size_bytes"] / (1024 * 1024) if e["size_bytes"] >= 0 else -1
        size = f"{mb:,.1f} MB" if mb >= 0 else "?"
        lines.append(f"- `{e['path']}` ({size})")
    return "\n".join(lines)


@mcp.tool(
    name="sift_server_info",
    annotations={
        "title": "Server & toolchain info",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def sift_server_info() -> str:
    """Report server configuration and which forensic tools are installed.

    Use this to verify the environment before running analysis: it shows the
    evidence/output roots and whether each underlying binary is available.

    Returns:
        str: JSON with roots, timeouts, and a tool->available map.
    """
    tools = [
        "mmls", "fsstat", "fls", "icat", "img_stat", "blkls", "tsk_recover",
        "foremost", "scalpel", "file", "md5sum", "sha1sum", "sha256sum",
        "vol", "vol.py",
        "log2timeline.py", "psort.py", "pinfo.py", "evtx_dump.py", "evtxexport",
        "exiftool", "strings", "binwalk", "xxd", "yara",
    ]
    info = {
        "server": "sift_mcp",
        "evidence_root": str(EVIDENCE_ROOT),
        "evidence_root_exists": EVIDENCE_ROOT.exists(),
        "output_root": str(SIFT_OUTPUT_ROOT),
        "default_timeout_s": DEFAULT_TIMEOUT,
        "max_output_chars": MAX_OUTPUT_CHARS,
        "bind": f"{HOST}:{PORT}",
        "tools": {t: _tool_available(t) for t in tools},
    }
    return json.dumps(info, indent=2)


# =========================================================================== #
# Disk / file analysis (The Sleuth Kit, foremost, file, hashing)
# =========================================================================== #

class ImageInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    image: str = Field(..., description="Path to the disk image, relative to the evidence root (e.g. 'case01/disk.dd', 'disk.E01').", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_disk_partitions",
    annotations={"title": "List disk image partitions (mmls)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_disk_partitions(params: ImageInput) -> str:
    """Show the partition layout of a disk image using The Sleuth Kit's `mmls`.

    Returns the partition table with the starting sector (offset) of each
    partition. You need a partition's start offset to run filesystem tools
    (sift_filesystem_info, sift_list_files) against that partition.

    Args:
        params (ImageInput): image path (under evidence root), format, timeout.

    Returns:
        str: mmls output (partition slots, start/length sectors, descriptions).
    """
    try:
        img = _evidence_path(params.image)
    except PathSecurityError as e:
        return f"Error: {e}"
    return await _run_and_format(
        ["mmls", str(img)], params.response_format, timeout=params.timeout,
        note="The 'Start' column is the partition offset in sectors. Pass it as 'offset' to filesystem tools.",
    )


@mcp.tool(
    name="sift_image_info",
    annotations={"title": "Disk image metadata (img_stat)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_image_info(params: ImageInput) -> str:
    """Show container metadata for a disk image using `img_stat`.

    Reports the image format (raw/EWF/etc.), byte size, and sector size. Useful
    to confirm an image is readable before deeper analysis.

    Args:
        params (ImageInput): image path, format, timeout.

    Returns:
        str: img_stat output.
    """
    try:
        img = _evidence_path(params.image)
    except PathSecurityError as e:
        return f"Error: {e}"
    return await _run_and_format(["img_stat", str(img)], params.response_format, timeout=params.timeout)


class FilesystemInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    image: str = Field(..., description="Path to the disk image, relative to the evidence root.", min_length=1)
    offset: Optional[int] = Field(default=None, description="Partition start sector offset (from sift_disk_partitions). Omit for a single-filesystem image.", ge=0)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_filesystem_info",
    annotations={"title": "Filesystem details (fsstat)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_filesystem_info(params: FilesystemInput) -> str:
    """Show filesystem details for a partition using `fsstat`.

    Reports filesystem type (NTFS, ext4, FAT, etc.), volume label, block/cluster
    size, and metadata layout.

    Args:
        params (FilesystemInput): image, optional partition offset, format, timeout.

    Returns:
        str: fsstat output.
    """
    try:
        img = _evidence_path(params.image)
    except PathSecurityError as e:
        return f"Error: {e}"
    argv = ["fsstat"]
    if params.offset is not None:
        argv += ["-o", str(params.offset)]
    argv.append(str(img))
    return await _run_and_format(argv, params.response_format, timeout=params.timeout)


class ListFilesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    image: str = Field(..., description="Path to the disk image, relative to the evidence root.", min_length=1)
    offset: Optional[int] = Field(default=None, description="Partition start sector offset (from sift_disk_partitions).", ge=0)
    inode: Optional[str] = Field(default=None, description="Directory inode/meta address to list (e.g. '5' for NTFS root). Omit to list the root directory.")
    recursive: bool = Field(default=False, description="Recurse into all subdirectories (can produce large output; use deleted=True to focus).")
    deleted_only: bool = Field(default=False, description="Show only deleted entries.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_list_files",
    annotations={"title": "List files in image (fls)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_list_files(params: ListFilesInput) -> str:
    """List files and directories inside a disk image partition using `fls`.

    Each line includes the file type, the inode/metadata address (e.g. `16-128-1`),
    and the name. Deleted entries are marked with `*`. Pass an inode to
    sift_extract_file to recover its contents.

    Args:
        params (ListFilesInput): image, offset, inode, recursive, deleted_only, format, timeout.

    Returns:
        str: fls output. Lines look like: `r/r 16-128-1: secret.docx`.
    """
    try:
        img = _evidence_path(params.image)
    except PathSecurityError as e:
        return f"Error: {e}"
    argv = ["fls"]
    if params.offset is not None:
        argv += ["-o", str(params.offset)]
    if params.recursive:
        argv.append("-r")
    if params.deleted_only:
        argv.append("-d")
    argv.append(str(img))
    if params.inode:
        argv.append(params.inode)
    return await _run_and_format(
        argv, params.response_format, timeout=params.timeout,
        note="Format: <type> <inode>: <name>. '*' marks deleted files. Use the inode with sift_extract_file.",
    )


class ExtractFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    image: str = Field(..., description="Path to the disk image, relative to the evidence root.", min_length=1)
    inode: str = Field(..., description="Inode / metadata address of the file to recover (from sift_list_files, e.g. '16-128-1').", min_length=1)
    output_name: str = Field(..., description="File name to write under the output root (e.g. 'case01/recovered/secret.docx').", min_length=1)
    offset: Optional[int] = Field(default=None, description="Partition start sector offset.", ge=0)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="Timeout in seconds.", ge=5, le=7200)

    @field_validator("inode")
    @classmethod
    def _validate_inode(cls, v: str) -> str:
        # TSK inode addresses are digits and dashes (e.g. 16-128-1); reject anything else.
        if not all(ch.isdigit() or ch == "-" for ch in v):
            raise ValueError("inode must contain only digits and dashes, e.g. '16-128-1'")
        return v


@mcp.tool(
    name="sift_extract_file",
    annotations={"title": "Recover file by inode (icat)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_extract_file(params: ExtractFileInput) -> str:
    """Recover a single file's contents from a disk image by inode using `icat`.

    Writes the recovered bytes to a file under the output root and reports its
    path, size, and SHA-256 hash so you can analyze it further or verify
    integrity. Works for both allocated and deleted files.

    Args:
        params (ExtractFileInput): image, inode, output_name, offset, format, timeout.

    Returns:
        str: Output path, byte size, and SHA-256 of the recovered file.
    """
    try:
        img = _evidence_path(params.image)
        out = _output_path(params.output_name)
    except PathSecurityError as e:
        return f"Error: {e}"

    out.parent.mkdir(parents=True, exist_ok=True)
    argv = ["icat"]
    if params.offset is not None:
        argv += ["-o", str(params.offset)]
    argv += [str(img), params.inode]

    try:
        rc, stdout, stderr = await _run(argv, timeout=params.timeout)
    except (FileNotFoundError, asyncio.TimeoutError) as e:
        return f"Error: {e}"

    if rc != 0:
        return _format_result(argv, rc, "", stderr, params.response_format, note="icat failed; check the inode and offset.")

    # icat streams file bytes to stdout; write them as raw bytes.
    data = stdout.encode("utf-8", errors="surrogateescape")
    try:
        out.write_bytes(data)
    except OSError as e:
        return f"Error: could not write output file '{out}': {e}"

    # Hash the recovered file for integrity.
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    rel = out.relative_to(SIFT_OUTPUT_ROOT)
    result = {
        "recovered_to": str(rel),
        "absolute_path": str(out),
        "size_bytes": len(data),
        "sha256": sha,
    }
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(result, indent=2)
    return (
        f"Recovered file to `{rel}` under the output root.\n\n"
        f"- **Size:** {len(data):,} bytes\n- **SHA-256:** `{sha}`\n"
        f"- **Absolute path:** `{out}`"
    )


class CarveInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    image: str = Field(..., description="Path to the disk image or unallocated-space blob, relative to the evidence root.", min_length=1)
    output_dir: str = Field(..., description="Directory under the output root to write carved files into (e.g. 'case01/carved').", min_length=1)
    file_types: Optional[str] = Field(default=None, description="Comma-separated foremost types to carve (e.g. 'jpg,pdf,doc,zip'). Omit to carve all configured types.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=1800, description="Timeout in seconds (carving is slow).", ge=10, le=14400)

    @field_validator("file_types")
    @classmethod
    def _validate_types(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        for t in v.split(","):
            t = t.strip()
            if t and not t.isalnum():
                raise ValueError(f"invalid file type '{t}'; use alphanumeric foremost type names like jpg,pdf,zip")
        return v


@mcp.tool(
    name="sift_carve_files",
    annotations={"title": "File carving (foremost)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
async def sift_carve_files(params: CarveInput) -> str:
    """Carve files from an image based on file signatures using `foremost`.

    Recovers files (images, documents, archives, etc.) by header/footer signature
    even when filesystem metadata is gone. Results, including foremost's
    `audit.txt` summary, are written under the output directory.

    Args:
        params (CarveInput): image, output_dir, optional file_types, format, timeout.

    Returns:
        str: foremost run summary plus the tail of audit.txt.
    """
    try:
        img = _evidence_path(params.image)
        outdir = _output_path(params.output_dir)
    except PathSecurityError as e:
        return f"Error: {e}"

    # foremost requires the output dir to not pre-exist (or use -T); use a fresh dir.
    if outdir.exists() and any(outdir.iterdir()):
        return (
            f"Error: output directory '{params.output_dir}' already exists and is not empty. "
            f"foremost needs an empty/new directory. Choose a new output_dir."
        )
    argv = ["foremost"]
    if params.file_types:
        argv += ["-t", ",".join(t.strip() for t in params.file_types.split(","))]
    argv += ["-o", str(outdir), "-i", str(img)]

    result = await _run_and_format(argv, params.response_format, timeout=params.timeout)

    audit = outdir / "audit.txt"
    if audit.exists():
        try:
            tail = "\n".join(audit.read_text(errors="replace").splitlines()[-40:])
            result += f"\n\n**audit.txt (tail):**\n```\n{tail}\n```"
        except OSError:
            pass
    return result


class FileTypeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to a file under the evidence or output root.", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")


def _resolve_any(path_str: str) -> Path:
    """Resolve a path that may live under either the evidence or output root."""
    try:
        return _resolve_under(path_str, EVIDENCE_ROOT, must_exist=True)
    except PathSecurityError:
        return _resolve_under(path_str, SIFT_OUTPUT_ROOT, must_exist=True)


@mcp.tool(
    name="sift_file_type",
    annotations={"title": "Identify file type (file)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_file_type(params: FileTypeInput) -> str:
    """Identify a file's type from its content signature using `file`.

    Works on evidence files and on files you have recovered/carved into the
    output root. Does not trust the extension.

    Args:
        params (FileTypeInput): path, format.

    Returns:
        str: The detected file type description.
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"
    return await _run_and_format(["file", str(target)], params.response_format)


class HashInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to a file under the evidence or output root.", min_length=1)
    algorithm: str = Field(default="sha256", description="Hash algorithm: 'md5', 'sha1', or 'sha256'.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="Timeout in seconds.", ge=5, le=7200)

    @field_validator("algorithm")
    @classmethod
    def _validate_algo(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"md5", "sha1", "sha256"}:
            raise ValueError("algorithm must be one of: md5, sha1, sha256")
        return v


@mcp.tool(
    name="sift_hash_file",
    annotations={"title": "Hash a file", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_hash_file(params: HashInput) -> str:
    """Compute a cryptographic hash of a file for integrity / IOC matching.

    Use md5/sha1/sha256 to fingerprint evidence or compare against known-bad
    hash sets.

    Args:
        params (HashInput): path, algorithm, format, timeout.

    Returns:
        str: The hash digest and file path.
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"
    binary = {"md5": "md5sum", "sha1": "sha1sum", "sha256": "sha256sum"}[params.algorithm]
    return await _run_and_format([binary, str(target)], params.response_format, timeout=params.timeout)


# =========================================================================== #
# Memory forensics (Volatility 3)
# =========================================================================== #

def _volatility_binary() -> Optional[str]:
    for candidate in ("vol", "vol.py", "volatility3", "vol3"):
        if _tool_available(candidate):
            return candidate
    return None


# Allowlist of commonly used Volatility 3 plugins. Freeform plugin names are also
# accepted but validated for shape to avoid argument injection.
COMMON_VOL_PLUGINS = [
    "windows.info", "windows.pslist", "windows.pstree", "windows.psscan",
    "windows.cmdline", "windows.dlllist", "windows.handles", "windows.netscan",
    "windows.netstat", "windows.malfind", "windows.svcscan", "windows.filescan",
    "windows.registry.hivelist", "windows.registry.printkey",
    "linux.pslist", "linux.pstree", "linux.bash", "linux.check_syscall",
    "mac.pslist",
]


class VolatilityInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    memory_dump: str = Field(..., description="Path to the memory image, relative to the evidence root (e.g. 'case01/memory.raw').", min_length=1)
    plugin: str = Field(..., description=f"Volatility 3 plugin to run (e.g. {', '.join(COMMON_VOL_PLUGINS[:6])}).", min_length=1)
    extra_args: Optional[List[str]] = Field(default=None, description="Optional extra plugin arguments as a list (e.g. ['--pid', '1234']). Each item is passed verbatim, no shell.", max_length=20)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=1800, description="Timeout in seconds (memory analysis is slow).", ge=10, le=14400)

    @field_validator("plugin")
    @classmethod
    def _validate_plugin(cls, v: str) -> str:
        # Plugin names are dotted identifiers, e.g. windows.pslist. Reject anything else.
        cleaned = v.strip()
        if not all(ch.isalnum() or ch in "._" for ch in cleaned):
            raise ValueError("plugin must be a dotted identifier like 'windows.pslist'")
        return cleaned

    @field_validator("extra_args")
    @classmethod
    def _validate_extra(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        for a in v:
            if a.startswith("-") and (" " in a or ";" in a or "|" in a):
                raise ValueError(f"suspicious argument '{a}'")
        return v


@mcp.tool(
    name="sift_volatility",
    annotations={"title": "Memory analysis (Volatility 3)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_volatility(params: VolatilityInput) -> str:
    """Run a Volatility 3 plugin against a memory image.

    Volatility extracts artifacts from RAM captures: running processes
    (windows.pslist / pstree), network connections (windows.netscan), injected
    code (windows.malfind), command lines (windows.cmdline), registry data, and
    more. Start with `windows.info` (or `linux.pslist`) to confirm the profile,
    then drill in.

    Args:
        params (VolatilityInput): memory_dump, plugin, extra_args, format, timeout.

    Returns:
        str: The plugin's tabular output.

    Examples:
        - "What processes were running?" -> plugin="windows.pslist"
        - "Any suspicious network connections?" -> plugin="windows.netscan"
        - "Show command line for PID 1234" -> plugin="windows.cmdline", extra_args=["--pid","1234"]
    """
    binary = _volatility_binary()
    if binary is None:
        return "Error: Volatility 3 is not installed (looked for vol, vol.py, volatility3). Install with: pipx install volatility3"
    try:
        dump = _evidence_path(params.memory_dump)
    except PathSecurityError as e:
        return f"Error: {e}"

    argv = [binary, "-f", str(dump), params.plugin]
    if params.extra_args:
        argv += params.extra_args

    note = None
    if params.plugin not in COMMON_VOL_PLUGINS:
        note = f"'{params.plugin}' is not in the common-plugin list; if it fails, run a known plugin like windows.info first."
    return await _run_and_format(argv, params.response_format, timeout=params.timeout, note=note)


# =========================================================================== #
# Timeline & artifacts (Plaso, EVTX)
# =========================================================================== #

class Log2TimelineInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    source: str = Field(..., description="Path to the source (disk image, directory, or file) under the evidence root.", min_length=1)
    storage_name: str = Field(..., description="Name of the .plaso storage file to create under the output root (e.g. 'case01/timeline.plaso').", min_length=1)
    parsers: Optional[str] = Field(default=None, description="Optional parser/preset filter (e.g. 'win7', 'webhist', 'winevtx'). Omit for auto-detection.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=7200, description="Timeout in seconds (timelining is very slow).", ge=30, le=43200)

    @field_validator("parsers")
    @classmethod
    def _validate_parsers(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        for p in v.replace("!", "").split(","):
            p = p.strip()
            if p and not all(ch.isalnum() or ch in "_-" for ch in p):
                raise ValueError(f"invalid parser name '{p}'")
        return v


@mcp.tool(
    name="sift_create_timeline",
    annotations={"title": "Build super-timeline (log2timeline)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
async def sift_create_timeline(params: Log2TimelineInput) -> str:
    """Extract timestamped events from a source into a Plaso storage file.

    Runs `log2timeline.py` to build a super-timeline storage (.plaso) from a disk
    image, directory, or file. After it completes, export a readable timeline
    with sift_export_timeline.

    Args:
        params (Log2TimelineInput): source, storage_name, optional parsers, format, timeout.

    Returns:
        str: log2timeline progress/summary and the storage file path.
    """
    try:
        source = _evidence_path(params.source)
        storage = _output_path(params.storage_name)
    except PathSecurityError as e:
        return f"Error: {e}"
    storage.parent.mkdir(parents=True, exist_ok=True)

    argv = ["log2timeline.py", "--status_view", "none"]
    if params.parsers:
        argv += ["--parsers", params.parsers]
    argv += [str(storage), str(source)]
    return await _run_and_format(
        argv, params.response_format, timeout=params.timeout,
        note=f"Storage written to '{params.storage_name}'. Export it with sift_export_timeline.",
    )


class PsortInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    storage_name: str = Field(..., description="Path to an existing .plaso storage file under the output OR evidence root.", min_length=1)
    output_name: str = Field(..., description="CSV timeline file to write under the output root (e.g. 'case01/timeline.csv').", min_length=1)
    output_format: str = Field(default="l2tcsv", description="psort output module: 'l2tcsv', 'dynamic', or 'json_line'.")
    date_filter: Optional[str] = Field(default=None, description="Optional date range filter, e.g. \"date > '2024-01-01' and date < '2024-02-01'\".")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=3600, description="Timeout in seconds.", ge=10, le=43200)

    @field_validator("output_format")
    @classmethod
    def _validate_outfmt(cls, v: str) -> str:
        v = v.strip()
        if v not in {"l2tcsv", "dynamic", "json_line", "json"}:
            raise ValueError("output_format must be one of: l2tcsv, dynamic, json_line, json")
        return v


@mcp.tool(
    name="sift_export_timeline",
    annotations={"title": "Export timeline (psort)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_export_timeline(params: PsortInput) -> str:
    """Export a Plaso storage file to a readable CSV/JSON timeline using `psort.py`.

    Optionally apply a date-range filter to keep the timeline focused. The result
    is written under the output root and a preview of the first rows is returned.

    Args:
        params (PsortInput): storage_name, output_name, output_format, date_filter, format, timeout.

    Returns:
        str: psort summary plus a preview (first ~30 lines) of the exported timeline.
    """
    # Storage may live in output (just created) or evidence (provided).
    try:
        storage = _resolve_any(params.storage_name)
    except PathSecurityError as e:
        return f"Error: {e}"
    try:
        out = _output_path(params.output_name)
    except PathSecurityError as e:
        return f"Error: {e}"
    out.parent.mkdir(parents=True, exist_ok=True)

    argv = ["psort.py", "-o", params.output_format, "-w", str(out), str(storage)]
    if params.date_filter:
        argv.append(params.date_filter)

    result = await _run_and_format(argv, params.response_format, timeout=params.timeout)
    if out.exists():
        try:
            preview = "\n".join(out.read_text(errors="replace").splitlines()[:30])
            result += f"\n\n**Preview of `{params.output_name}`:**\n```\n{preview}\n```"
        except OSError:
            pass
    return result


class EvtxInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    evtx_file: str = Field(..., description="Path to a Windows .evtx event log file under the evidence or output root.", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=600, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_parse_evtx",
    annotations={"title": "Parse Windows event log (.evtx)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_parse_evtx(params: EvtxInput) -> str:
    """Parse a Windows .evtx event log into readable XML records.

    Uses `evtx_dump.py` (python-evtx) when available, falling back to
    `evtxexport`. Useful for examining security, system, and application logs
    pulled from a host or recovered from an image.

    Args:
        params (EvtxInput): evtx_file, format, timeout.

    Returns:
        str: The decoded event records (truncated if large).
    """
    try:
        target = _resolve_any(params.evtx_file)
    except PathSecurityError as e:
        return f"Error: {e}"

    if _tool_available("evtx_dump.py"):
        argv = ["evtx_dump.py", str(target)]
    elif _tool_available("evtxexport"):
        argv = ["evtxexport", str(target)]
    else:
        return "Error: no EVTX parser installed. Install python-evtx (pip install python-evtx) or libevtx-utils."
    return await _run_and_format(argv, params.response_format, timeout=params.timeout)


# =========================================================================== #
# Metadata & strings (exiftool, strings, binwalk, xxd, yara)
# =========================================================================== #

class ExiftoolInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to the file under the evidence or output root.", min_length=1)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=300, description="Timeout in seconds.", ge=5, le=3600)


@mcp.tool(
    name="sift_exiftool",
    annotations={"title": "Extract metadata (exiftool)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_exiftool(params: ExiftoolInput) -> str:
    """Extract embedded metadata from a file using `exiftool`.

    Reveals EXIF (camera, GPS, timestamps) for images and document metadata
    (author, software, creation/modification dates) for office/PDF files.

    Args:
        params (ExiftoolInput): path, format, timeout.

    Returns:
        str: All extracted metadata tags.
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"
    return await _run_and_format(["exiftool", str(target)], params.response_format, timeout=params.timeout)


class StringsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to the file under the evidence or output root.", min_length=1)
    min_length: int = Field(default=6, description="Minimum string length to report.", ge=1, le=1000)
    encoding: str = Field(default="s", description="strings encoding: 's' (ASCII), 'l' (16-bit LE), 'b' (16-bit BE).")
    grep: Optional[str] = Field(default=None, description="Optional case-insensitive substring to filter results (applied server-side).")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=600, description="Timeout in seconds.", ge=5, le=7200)

    @field_validator("encoding")
    @classmethod
    def _validate_enc(cls, v: str) -> str:
        v = v.strip()
        if v not in {"s", "S", "l", "b", "L", "B"}:
            raise ValueError("encoding must be one of: s, l, b")
        return v


@mcp.tool(
    name="sift_strings",
    annotations={"title": "Extract strings", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_strings(params: StringsInput) -> str:
    """Extract printable strings from a binary file using `strings`.

    Optionally filter results by a substring (e.g. 'http', 'password', a domain)
    to find IOCs, URLs, or config values inside binaries and memory artifacts.

    Args:
        params (StringsInput): path, min_length, encoding, grep, format, timeout.

    Returns:
        str: Matching strings (filtered by 'grep' if provided, truncated if large).
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"

    argv = ["strings", "-n", str(params.min_length), "-e", params.encoding, str(target)]
    try:
        rc, out, err = await _run(argv, timeout=params.timeout)
    except (FileNotFoundError, asyncio.TimeoutError) as e:
        return f"Error: {e}"

    if params.grep:
        needle = params.grep.lower()
        out = "\n".join(line for line in out.splitlines() if needle in line.lower())
        if not out.strip():
            return f"No strings containing '{params.grep}' found in {params.path}."
    return _format_result(argv, rc, out, err, params.response_format)


class BinwalkInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to the file under the evidence or output root.", min_length=1)
    extract: bool = Field(default=False, description="Also extract identified embedded files (written next to source under output root).")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=900, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_binwalk",
    annotations={"title": "Analyze embedded data (binwalk)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_binwalk(params: BinwalkInput) -> str:
    """Scan a file for embedded files and signatures using `binwalk`.

    Identifies embedded archives, filesystems, and firmware components. With
    extract=True it carves out the embedded objects (useful for firmware and
    container files).

    Args:
        params (BinwalkInput): path, extract, format, timeout.

    Returns:
        str: binwalk signature scan results.
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"
    argv = ["binwalk"]
    if params.extract:
        # Direct extraction output under the output root.
        argv += ["-e", "--directory", str(SIFT_OUTPUT_ROOT)]
    argv.append(str(target))
    return await _run_and_format(argv, params.response_format, timeout=params.timeout)


class HexdumpInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Path to the file under the evidence or output root.", min_length=1)
    offset: int = Field(default=0, description="Byte offset to start the dump.", ge=0)
    length: int = Field(default=512, description="Number of bytes to dump.", ge=1, le=1048576)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")


@mcp.tool(
    name="sift_hexdump",
    annotations={"title": "Hex dump a file region (xxd)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_hexdump(params: HexdumpInput) -> str:
    """Show a hex + ASCII dump of a byte range of a file using `xxd`.

    Useful for inspecting file headers/magic bytes, examining structure, or
    eyeballing a region of a carved artifact.

    Args:
        params (HexdumpInput): path, offset, length, format.

    Returns:
        str: The hex dump of the requested region.
    """
    try:
        target = _resolve_any(params.path)
    except PathSecurityError as e:
        return f"Error: {e}"
    argv = ["xxd", "-s", str(params.offset), "-l", str(params.length), str(target)]
    return await _run_and_format(argv, params.response_format, timeout=120)


class YaraInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    rules_file: str = Field(..., description="Path to a YARA rules (.yar/.yara) file under the evidence or output root.", min_length=1)
    target: str = Field(..., description="File or directory to scan, under the evidence or output root.", min_length=1)
    recursive: bool = Field(default=False, description="Scan directories recursively.")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format.")
    timeout: int = Field(default=900, description="Timeout in seconds.", ge=5, le=7200)


@mcp.tool(
    name="sift_yara_scan",
    annotations={"title": "Scan with YARA rules", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
async def sift_yara_scan(params: YaraInput) -> str:
    """Scan files or a directory against YARA rules to detect malware/IOCs.

    Matches the provided rule set against the target and reports which rules hit
    which files. Both the rules file and the target must live under the evidence
    or output root.

    Args:
        params (YaraInput): rules_file, target, recursive, format, timeout.

    Returns:
        str: Matching `rule_name file_path` lines, or a no-match message.
    """
    try:
        rules = _resolve_any(params.rules_file)
        target = _resolve_any(params.target)
    except PathSecurityError as e:
        return f"Error: {e}"
    argv = ["yara"]
    if params.recursive:
        argv.append("-r")
    argv += [str(rules), str(target)]
    return await _run_and_format(
        argv, params.response_format, timeout=params.timeout,
        note="Each output line is '<rule_name> <matched_path>'. No lines means no matches.",
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    _ensure_roots()
    transport = os.environ.get("SIFT_TRANSPORT", "streamable-http")
    if transport == "stdio":
        mcp.run()
    else:
        # Streamable HTTP exposes the server at http://<host>:<port>/mcp
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
