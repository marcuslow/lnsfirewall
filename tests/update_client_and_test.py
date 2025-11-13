#!/usr/bin/env python3
"""
Update the pfSense client with the fixed parser and request fresh logs
"""

import asyncio
import aiohttp

HQ_URL = "http://localhost:8000"
CLIENT_ID = "opus-1"


async def main():
    print("🔄 Step 1: Pushing updated client code to pfSense...")
    
    async with aiohttp.ClientSession() as session:
        # Push client update
        async with session.post(f"{HQ_URL}/update-client", json={
            "client_id": CLIENT_ID,
            "files": ["pfsense_client.py"]
        }) as resp:
            if resp.status == 200:
                result = await resp.json()
                command_id = result.get("command_id")
                print(f"✅ Update command queued: {command_id}")
                
                # Wait for update to complete
                print("⏳ Waiting for client update...")
                for i in range(15):
                    await asyncio.sleep(2)
                    async with session.get(f"{HQ_URL}/command/{command_id}") as check_resp:
                        if check_resp.status == 200:
                            status_data = await check_resp.json()
                            if status_data.get("status") == "completed":
                                print(f"✅ Client updated successfully")
                                break
                            elif status_data.get("status") == "failed":
                                print(f"❌ Client update failed: {status_data.get('response_data')}")
                                return
                    print(f"   Still waiting... ({i+1}/15)")
            else:
                print(f"❌ Failed to queue update: {resp.status}")
                return
        
        # Wait a bit for client to restart
        print("\n⏳ Waiting for client to restart with new code...")
        await asyncio.sleep(5)
        
        # Request fresh logs
        print("\n📋 Step 2: Requesting fresh logs with fixed parser...")
        async with session.post(f"{HQ_URL}/command", json={
            "client_id": CLIENT_ID,
            "command_type": "get_logs",
            "params": {"days": 1}
        }) as resp:
            if resp.status == 200:
                result = await resp.json()
                command_id = result.get("command_id")
                print(f"✅ Log request queued: {command_id}")
                
                # Wait for logs
                print("⏳ Waiting for logs to be collected...")
                for i in range(60):
                    await asyncio.sleep(2)
                    async with session.get(f"{HQ_URL}/command/{command_id}") as check_resp:
                        if check_resp.status == 200:
                            status_data = await check_resp.json()
                            if status_data.get("status") == "completed":
                                print(f"✅ Logs collected successfully")
                                break
                            elif status_data.get("status") == "failed":
                                print(f"❌ Log collection failed: {status_data.get('response_data')}")
                                return
                    if i % 5 == 0:
                        print(f"   Still waiting... ({i+1}/60)")
            else:
                print(f"❌ Failed to queue log request: {resp.status}")
                return
    
    print("\n✅ Done! Now run: python analyze_unparsed_impact.py")


if __name__ == "__main__":
    asyncio.run(main())

