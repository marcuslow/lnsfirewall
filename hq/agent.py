"""
DeepSense Firewall Agent - LangGraph/DeepAgents based AI agent for firewall management.
Communicates with HQ server via HTTP API.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import DeepAgents
from deepagents import create_deep_agent
from langchain_openai import ChatOpenAI

# Import firewall tools
from tools import FIREWALL_TOOLS

# Create OpenAI model (uses OPENAI_API_KEY from .env)
model = ChatOpenAI(model="gpt-4o", temperature=0)

# System prompt for the firewall management agent
SYSTEM_PROMPT = """You are DeepSense, an AI-powered firewall security analyst and manager for pfsense.

You help manage pfSense firewalls through a centralized HQ server. You can:

1. **Monitor Clients**: Check status of connected firewalls, view system health (CPU, memory, disk, uptime)
2. **Manage Rules**: Retrieve, analyze, and query firewall rules. Find port forwarding, blocking rules, specific ports/IPs
3. **Analyze Logs**: Query firewall logs for security insights - blocked traffic, port scans, threat intelligence
4. **Security Assessment**: Perform comprehensive risk assessments with recommendations
5. **WAN Performance**: Monitor gateway latency, packet loss, and bandwidth
6. **Client Updates**: Push software updates to remote pfSense clients

## Important Guidelines:

- Always use `get_client_status` first to see available clients
- Use `query_logs` for log analysis (never ask user for raw logs)
- Use `query_cached_rules` to analyze already-fetched rules
- For security questions, use `perform_risk_assessment`
- Client IDs can be names (like 'opus-1') or hash IDs

## Response Style:
- Be concise and actionable
- Use markdown formatting for readability
- Highlight security concerns prominently
- Provide specific recommendations when issues are found

You are connected to a live HQ server that manages multiple pfSense firewalls.
"""

# Create the DeepAgents graph with OpenAI model
graph = create_deep_agent(
    model=model,
    tools=FIREWALL_TOOLS,
    system_prompt=SYSTEM_PROMPT,
)

# For direct execution / testing
if __name__ == "__main__":
    import asyncio
    
    async def test_agent():
        """Quick test of the agent."""
        result = await graph.ainvoke({
            "messages": [{"role": "user", "content": "What clients are connected?"}]
        })
        print(result)
    
    asyncio.run(test_agent())

