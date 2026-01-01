import asyncio
import re
from groq import Groq
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client, StdioServerParameters
import json
from app.services.util import opt, opt1

SYSTEM_PROMT = """You MUST follow these rules:
1. If the message start with "Prompt: " then response as usual
2. If the message start with "HTTP request JSON: " then parse JSON to get values and analysis each value carefully as a SOC analysis, think more and response what attack types are there in that request from 1 to 3 words each attack type, delimite each attack type with a comma. Do not mention generic attack types like authentication bypass, pasword brute force, etc.
3. If user request writing ModSecurity rules, you MUST read existing rule, message will start with "Rules: ".
4. If end writing rules, respond "End!"
5. If the message is in't anycase on above rules, ignore it
"""

class MCPClient:
    def __init__(self):
        self.session: ClientSession = None
        self.exit_stack = AsyncExitStack()
        self.groq = Groq(api_key="<your_key_goes_here>")

    async def connect_to_server(self, script_path: str):
        server = StdioServerParameters(
            command="python3",
            args=[script_path],
            env=None
        )
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
        await self.session.initialize()
        tools = await self.session.list_tools()
        print("Connected to MCP server. Tools:", [t.name for t in tools.tools])
    
    async def call_llm(self, prompt: str) -> str:
        new_rules_written = False
        res = await self.session.list_tools()
        available_tools = [{
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.inputSchema 
            }
        } for tool in res.tools]
        messages = [
            {"role": "system", "content": SYSTEM_PROMT},
            {"role": "user", "content": prompt}
        ]
        attack_type_detected = False
        while not new_rules_written:
            completion_args = {
                "model": "openai/gpt-oss-120b",
                "messages": messages,
                "temperature": 1,
                "max_completion_tokens": 8192,
                "top_p": 1,
                "reasoning_effort": "medium",
            }
            # Always expose tools so model tool calls are valid
            if available_tools:
                completion_args["tools"] = available_tools
                completion_args["tool_choice"] = "auto"
            res = self.groq.chat.completions.create(**completion_args)
            tools_call = res.choices[0].message.tool_calls
            message = res.choices[0].message.content
            print("LLM message:", message)
            if attack_type_detected is False:
                attack_type_detected = True
                if message:
                    messages.append({
                        "role": "assistant",
                        "content": message
                    })
                    messages.append({
                        "role": "user",
                        "content": f"Prompt: Act as a SOC analysis/red teamer, explain {message} in detail at a defensive/conceptual level, and describe how payloads typically look from simple -> intermediate -> advanced. Use short, high-level examples only."
                    })
                    res = self.groq.chat.completions.create(**completion_args)
                    message = res.choices[0].message.content
                    print("LLM message:", message)
                if message:
                    messages.append({
                        "role": "assistant",
                        "content": message
                    })
                    messages.append({
                        "role": "user",
                        "content": """Prompt: Act as a SOC analyst and WAF engineer. Based on your response, write ModSecurity rules to detect and block web attack techniques and payloads similar to the provided request using Anomaly Scoring, strictly following the OWASP ModSecurity Core Rule Set (CRS) methodology.

Requirements (MUST follow exactly):

- No output, no explain. Just write rules to file using the tool.
- Use CRS anomaly scoring:
  - Detection rules ONLY add score (PASS or LOG only). (setvar:tx.anomaly_score=+{score})
  - EXACTLY ONE final rule blocks when cumulative score >= threshold.
- Final blocking rule MUST run in phase:2 and include %{tx.anomaly_score} in the message. Example: SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:1009,phase:2,deny,status:403,log,msg:'Inbound anomaly score %{tx.anomaly_score} exceeded threshold %{tx.inbound_anomaly_score_threshold}',severity:2,tag:'security-attack',tag:'anomaly-score'"
- Cleanup/reset logic (if any) MUST be in phase:5 only.
- Detection rules MUST NOT block traffic.

- Always initialize anomaly score for each request: use tx.anomaly_score=0 and tx.inbound_anomaly_score_threshold=10

- Inspect payloads ONLY via parsed parameters:
  ARGS, ARGS_NAMES, REQUEST_HEADERS, REQUEST_COOKIES, REQUEST_URI.
  Do NOT inspect raw REQUEST_BODY.
  Assume all common body formats (form, multipart, JSON) are parsed into ARGS.

- Apply these transformations in EVERY detection rule:
  t:urlDecodeUni, t:lowercase, t:compressWhitespace

- Regex quality rules:
  - Do NOT match keywords, quotes, or comment markers alone.
  - Regex MUST express attack intent with context.
  - Avoid unbounded ".*" unless strictly necessary.

- Cover multiple attack classe, such as:
  SQLi, XSS, command injection, path traversal, SSRF, template injection.
  Use low-noise, intent-based patterns.

- Each rule MUST include CRS-style metadata:
  id, phase, msg, severity (numeric), and tags
  (include tag:'security-attack' plus specific tags like attack-sqli, attack-xss, etc.).

- Write rule to file custom.conf

- If ANY detection rule blocks traffic before the final score rule, the output is INVALID.

Generate the final ModSecurity rule set accordingly."""
                })
            res = self.groq.chat.completions.create(**completion_args)
            message = res.choices[0].message.content
            print("LLM message:", message)
            if message is not None:
                if "End!" in message:
                    new_rules_written = True
                    print("New rules have been written.")
                    break
            if tools_call:
                for tool in tools_call:
                    print(f"Calling tool: {tool.function.name}")
                    parsed_arguments = json.loads(tool.function.arguments)
                    if tool.function.name == "write_to_file": 
                        result = await self.session.call_tool(
                            "write_to_file",
                            {
                                "content": opt(parsed_arguments["content"]) + "\n",
                                "file_name": parsed_arguments["file_name"]
                            }
                        )
                        # Stop further LLM calls after a successful write
                        new_rules_written = True
                        print("Tool call result:", result)
                    elif tool.function.name == "read_rule_file":
                        result = await self.session.call_tool(
                            "read_rule_file",
                            {
                                "file_name": parsed_arguments["file_name"]
                            }
                        )
                        messages.append({
                            "role": "user",
                            "content": "Rules:\n" + result.content[0].text
                        })
                        print("Tool call result:", result)
                    elif tool.function.name == "rewrite_rule_file":
                        result = await self.session.call_tool(
                            "rewrite_rule_file",
                            {
                                "content": opt1(parsed_arguments["content"]) + "\n",
                                "file_name": parsed_arguments["file_name"]
                            }
                        )
                        # Stop further LLM calls after a successful rewrite
                        new_rules_written = True
                        print("Tool call result:", result)
                    else:
                        pass
                if new_rules_written:
                    print("New rules have been written.")
                    break
    
    async def close(self):
        await self.exit_stack.aclose()

def run_mcp_client(prompt: str, script_path: str = "app/services/mcp_server.py"):
    async def runner():
        client = MCPClient()
        try:
            await client.connect_to_server(script_path)
            await client.call_llm(prompt)
        finally:
            await client.close()
    
    asyncio.run(runner())