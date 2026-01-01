from typing import Any
from mcp.server.fastmcp import FastMCP
import threading

mcp = FastMCP("rule_writer")

@mcp.tool(name="write_to_file", description="Write provided ModSecurity rules into rule file (append). Argument: content: str, file_name: str")
def write_to_file(content: str, file_name: str) -> str:
    with open("/rules/" + "custom.conf", "a") as file:
        file.write(content)
    return f"Content written to {file_name}"

@mcp.tool(name="rewrite_rule_file", description="Rewrite the rule file with provided content. Argument: content: str, file_name: str")
def rewrite_rule_file(content: str, file_name: str) -> str:
    with open("/rules/" + "custom.conf", "w") as file:
        file.write(content)
    return f"Rewritten {file_name}"

@mcp.tool(name="read_rule_file", description="Read the current rules.txt. Returns empty string if file not found or file empty. Files' names are sqli.conf, xss.conf, path_traversal.conf, cmdi.conf, custom.conf.  Argument: file_name: str")
def read_rule_file(file_name: str) -> str:
    try:
        with open("/rules/" + file_name, "r") as file:
            return file_name + "\n" + file.read()
    except FileNotFoundError:
        return ""

def _run():
    mcp.run(transport="stdio")

def start_mcp_server():
    t = threading.Thread(target=_run, daemon=True)
    t.start()

if __name__ == "__main__":
    mcp.run(transport="stdio")