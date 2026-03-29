import argparse
import copy
import http.client
import json
import os
import sys
import traceback
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc
except ImportError:
    from installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc

# ---------------------------------------------------------------------------
# Multi-instance registry
# Maps instance label -> (host, port)
# ---------------------------------------------------------------------------

IDA_INSTANCES: dict[str, tuple[str, int]] = {}
_DEFAULT_INSTANCE_NAME: str = "default"

# Legacy single-instance globals kept for backwards compat with installer
IDA_HOST = "127.0.0.1"
IDA_PORT = 13337


def _register_instance(label: str, host: str, port: int) -> None:
    global _DEFAULT_INSTANCE_NAME
    IDA_INSTANCES[label] = (host, port)
    if len(IDA_INSTANCES) == 1:
        _DEFAULT_INSTANCE_NAME = label


def _call_ida(host: str, port: int, payload: bytes | str | dict, request_id) -> "JsonRpcResponse":
    """Make one HTTP call to an IDA plugin server. Returns a JsonRpcResponse dict."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    try:
        conn = http.client.HTTPConnection(host, port, timeout=30)
        try:
            conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
            response = conn.getresponse()
            raw_data = response.read().decode()
            if response.status >= 400:
                raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw_data}")
            return json.loads(raw_data)
        finally:
            conn.close()
    except Exception as e:
        full_info = traceback.format_exc()
        if request_id is None:
            return None  # Notification, no response needed
        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


def _error_response(request_id, message: str) -> "JsonRpcResponse":
    return JsonRpcResponse(
        {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": message, "data": message},
            "id": request_id,
        }
    )


def _inject_instance_param(tool: dict, instance_names: list[str]) -> dict:
    """Add an optional _instance property to a tool's inputSchema."""
    tool = copy.deepcopy(tool)
    schema = tool.setdefault("inputSchema", {})
    schema.setdefault("type", "object")
    props = schema.setdefault("properties", {})
    default = instance_names[0] if instance_names else ""
    props["_instance"] = {
        "type": "string",
        "description": (
            f"Which IDA instance to target. Available: {', '.join(instance_names)}. "
            f"Default: '{default}' (first registered)."
        ),
        "enum": instance_names,
    }
    return tool


def _handle_tools_list(request_obj: dict, request_id) -> "JsonRpcResponse":
    """Return merged tool list: local bridge tools + IDA tools (with _instance injected)."""
    instance_names = list(IDA_INSTANCES.keys())

    # Get local bridge tools (list_instances, call_tool_on_instance)
    local_resp = dispatch_original(request_obj)
    local_tools: list[dict] = []
    if isinstance(local_resp, dict):
        local_tools = (local_resp.get("result") or {}).get("tools", [])

    # Get IDA tools from the default instance
    ida_tools: list[dict] = []
    if IDA_INSTANCES:
        host, port = IDA_INSTANCES[_DEFAULT_INSTANCE_NAME]
        ida_resp = _call_ida(host, port, request_obj, request_id)
        if isinstance(ida_resp, dict) and "result" in ida_resp:
            ida_tools = (ida_resp["result"] or {}).get("tools", [])

    # Inject _instance into every IDA tool so the AI knows the parameter exists
    if len(instance_names) > 1:
        ida_tools = [_inject_instance_param(t, instance_names) for t in ida_tools]

    merged = local_tools + ida_tools
    return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": merged}}


def dispatch_proxy(request: dict | str | bytes | bytearray) -> "JsonRpcResponse | None":
    """Dispatch JSON-RPC requests — routes to local registry or a named IDA instance."""
    if not isinstance(request, dict):
        request_obj: "JsonRpcRequest" = json.loads(request)
    else:
        request_obj: "JsonRpcRequest" = request  # type: ignore

    method = request_obj.get("method", "")
    request_id = request_obj.get("id")

    # Always handle initialize and notifications locally
    if method == "initialize" or method.startswith("notifications/"):
        return dispatch_original(request)

    # Merge local bridge tools with IDA tools and advertise _instance on each
    if method == "tools/list":
        return _handle_tools_list(request_obj, request_id)

    # For tools/call, check if the caller wants a specific IDA instance
    if method == "tools/call":
        params = request_obj.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}

        # Bridge tools are handled locally — don't forward them
        if tool_name in ("list_instances", "call_tool_on_instance"):
            return dispatch_original(request)

        # Extract optional _instance selector, default to first registered instance
        instance_name = arguments.get("_instance", _DEFAULT_INSTANCE_NAME)

        if not IDA_INSTANCES:
            return _error_response(
                request_id,
                "No IDA instances registered. Start ida-pro-mcp with --ida-rpc.",
            )

        if instance_name not in IDA_INSTANCES:
            known = ", ".join(repr(k) for k in IDA_INSTANCES)
            return _error_response(
                request_id,
                f"Unknown IDA instance {instance_name!r}. Known instances: {known}",
            )

        host, port = IDA_INSTANCES[instance_name]

        # Strip _instance from the forwarded payload so IDA doesn't see it
        if "_instance" in arguments:
            request_obj = copy.deepcopy(request_obj)
            request_obj["params"]["arguments"] = {
                k: v for k, v in arguments.items() if k != "_instance"
            }

        payload: bytes | str | dict = request_obj
        return _call_ida(host, port, payload, request_id)

    # All other methods (resources/*, etc.) — forward to default instance
    if not IDA_INSTANCES:
        return _error_response(
            request_id,
            "No IDA instances registered. Start ida-pro-mcp with --ida-rpc.",
        )

    host, port = IDA_INSTANCES[_DEFAULT_INSTANCE_NAME]
    return _call_ida(host, port, request, request_id)


mcp.registry.dispatch = dispatch_proxy


# ---------------------------------------------------------------------------
# Bridge tools — registered on the MCP server, handled locally (no IDA call)
# ---------------------------------------------------------------------------


def _make_tools_call_payload(tool_name: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    }


@mcp.tool
def list_instances() -> list[dict]:
    """List all registered IDA instances. Use instance labels as the '_instance' argument in any tool call."""
    result = []
    for label, (host, port) in IDA_INSTANCES.items():
        result.append(
            {
                "label": label,
                "host": host,
                "port": port,
                "url": f"http://{host}:{port}",
                "is_default": label == _DEFAULT_INSTANCE_NAME,
            }
        )
    return result


@mcp.tool
def call_tool_on_instance(
    instance: str,
    tool: str,
    arguments: dict = None,
) -> dict:
    """Call any IDA tool on a specific named instance.

    Use this to explicitly target one IDA instance when you need to read from one
    (e.g. 'mac') and write to another (e.g. 'win'). Equivalent to adding
    '_instance': '<instance>' to any tool's arguments, but more explicit.

    Example:
        call_tool_on_instance("mac", "list_funcs", {"queries": "*"})
        call_tool_on_instance("win", "rename_func", {"addr": "0x401000", "name": "PlayerInit"})
    """
    if instance not in IDA_INSTANCES:
        known = ", ".join(repr(k) for k in IDA_INSTANCES)
        return {"error": f"Unknown instance {instance!r}. Known: {known}"}

    host, port = IDA_INSTANCES[instance]
    payload = _make_tools_call_payload(tool, arguments or {})
    result = _call_ida(host, port, payload, 1)
    if result is None:
        return {"error": "No response from IDA instance (notification?)"}
    # Unwrap the JSON-RPC envelope and return just the tool result
    if "error" in result:
        return {"error": result["error"].get("message", str(result["error"]))}
    return result.get("result", result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_ida_rpc(value: str) -> tuple[str, str, int]:
    """Parse 'name=url' or bare 'url'. Returns (label, host, port)."""
    if "=" in value and not value.startswith("http"):
        label, _, url_part = value.partition("=")
        label = label.strip()
    else:
        label = None
        url_part = value

    parsed = urlparse(url_part)
    if parsed.hostname is None or parsed.port is None:
        raise argparse.ArgumentTypeError(
            f"Invalid IDA RPC value {value!r}. "
            "Expected 'http://host:port' or 'name=http://host:port'."
        )
    return label, parsed.hostname, parsed.port


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        action="append",
        dest="ida_rpcs",
        metavar="[NAME=]URL",
        default=None,
        help="IDA RPC endpoint. May be specified multiple times for multiple instances. "
        "Format: 'http://host:port' (single default instance) or "
        "'name=http://host:port' (named instance, e.g. 'mac=http://127.0.0.1:13337'). "
        f"Default: http://{IDA_HOST}:{IDA_PORT}",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Parse IDA RPC arguments
    ida_rpcs_raw = args.ida_rpcs or [f"http://{IDA_HOST}:{IDA_PORT}"]
    seen_labels: dict[str, int] = {}  # label -> count for auto-numbering dupes
    for raw in ida_rpcs_raw:
        try:
            label, host, port = _parse_ida_rpc(raw)
        except argparse.ArgumentTypeError as e:
            print(f"Error: {e}")
            sys.exit(1)

        # Auto-assign label if not provided
        if label is None:
            label = "default" if not IDA_INSTANCES else f"instance{len(IDA_INSTANCES) + 1}"

        # Deduplicate labels
        if label in IDA_INSTANCES:
            seen_labels[label] = seen_labels.get(label, 0) + 1
            label = f"{label}{seen_labels[label]}"

        _register_instance(label, host, port)

    # Keep legacy single-instance globals in sync (for installer compat)
    if IDA_INSTANCES:
        first_host, first_port = next(iter(IDA_INSTANCES.values()))
        IDA_HOST = first_host
        IDA_PORT = first_port
        set_ida_rpc(IDA_HOST, IDA_PORT)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    if len(IDA_INSTANCES) > 1:
        print(f"[ida-pro-mcp] Multi-instance mode: {len(IDA_INSTANCES)} IDA instances")
        for label, (host, port) in IDA_INSTANCES.items():
            default_marker = " (default)" if label == _DEFAULT_INSTANCE_NAME else ""
            print(f"  {label!r}: http://{host}:{port}{default_marker}")

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
