#!/usr/bin/env python3
"""
AI Console Q&A Test Suite

Tests all AI Command Center capabilities with natural language questions.
Uses AI to evaluate if responses are logical and accurate.
"""
import asyncio
import json
import os
import sys
import time
import requests
from datetime import datetime
from typing import Dict, List, Any
from dotenv import load_dotenv
import openai

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hq.ai_command_center import AICommandCenter

# Load environment variables
load_dotenv()

# Server configuration
HQ_SERVER_URL = "http://localhost:8000"

# Test questions covering all capabilities
TEST_QUESTIONS = [
    {
        "id": 1,
        "category": "Client Status",
        "question": "What is the connection status of opus-1?",
        "expected_info": [
            "last connected time",
            "connection status (online/offline)",
            "uptime or last seen timestamp"
        ],
        "evaluation_criteria": "Response should include when the client last connected and current connection status"
    },
    {
        "id": 2,
        "category": "System Resources",
        "question": "Show me the disk space and memory usage for opus-1",
        "expected_info": [
            "disk space usage (used/total)",
            "memory usage (used/total)",
            "percentage or specific values"
        ],
        "evaluation_criteria": "Response should include both disk and memory metrics with actual values"
    },
    {
        "id": 3,
        "category": "Tool 1 - Traffic Anomaly",
        "question": "What are the top blocked IPs attacking opus-1 in the last 7 days?",
        "expected_info": [
            "list of IP addresses",
            "number of blocks per IP",
            "time period analyzed"
        ],
        "evaluation_criteria": "Response should list specific IPs with block counts, sorted by frequency"
    },
    {
        "id": 4,
        "category": "Tool 2 - Port Scanning",
        "question": "Has opus-1 detected any port scanning activity recently?",
        "expected_info": [
            "number of scans detected",
            "vertical or horizontal scans",
            "source IPs of scanners"
        ],
        "evaluation_criteria": "Response should indicate if port scans were detected and provide details or confirm none found"
    },
    {
        "id": 5,
        "category": "Tool 3 - Geographic Analysis",
        "question": "Which countries are the attacks on opus-1 coming from?",
        "expected_info": [
            "list of countries",
            "number of attacks per country",
            "percentage or ranking"
        ],
        "evaluation_criteria": "Response should list countries with attack counts or percentages, ideally ranked"
    },
    {
        "id": 6,
        "category": "Tool 4 - Threat Intelligence",
        "question": "Are there any known malicious IPs attacking opus-1?",
        "expected_info": [
            "number of malicious IPs found",
            "confidence scores or threat levels",
            "specific malicious IPs with details"
        ],
        "evaluation_criteria": "Response should indicate if malicious IPs were found with threat intelligence data"
    },
    {
        "id": 7,
        "category": "Tool 5 - Outbound Anomaly",
        "question": "Is there any suspicious outbound traffic from opus-1?",
        "expected_info": [
            "number of suspicious connections",
            "internal hosts involved",
            "destination IPs or confirmation of no issues"
        ],
        "evaluation_criteria": "Response should indicate if suspicious outbound traffic exists or confirm network is clean"
    },
    {
        "id": 8,
        "category": "Security Assessment",
        "question": "Give me a comprehensive security assessment of opus-1",
        "expected_info": [
            "overall risk level",
            "summary of threats detected",
            "recommendations",
            "multiple security metrics"
        ],
        "evaluation_criteria": "Response should provide holistic security overview combining multiple analysis tools"
    },
    {
        "id": 9,
        "category": "Specific Threat",
        "question": "What ports are being targeted the most on opus-1?",
        "expected_info": [
            "list of port numbers",
            "number of attempts per port",
            "service names (SSH, RDP, etc.)"
        ],
        "evaluation_criteria": "Response should list specific ports with attack counts"
    },
    {
        "id": 10,
        "category": "Time-based Query",
        "question": "Show me the security summary for opus-1 over the last 24 hours",
        "expected_info": [
            "time period confirmation (24 hours)",
            "blocked events count",
            "key threats or all-clear status"
        ],
        "evaluation_criteria": "Response should focus on 24-hour timeframe and provide relevant security metrics"
    }
]


class AIEvaluator:
    """Uses OpenAI to evaluate if AI Console responses are logical and accurate"""
    
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
    
    def evaluate_response(
        self,
        question: str,
        response: str,
        expected_info: List[str],
        criteria: str
    ) -> Dict[str, Any]:
        """
        Evaluate if the AI Console response is logical and meets expectations
        
        Returns:
            {
                "pass": bool,
                "score": int (0-100),
                "reasoning": str,
                "missing_info": List[str]
            }
        """
        evaluation_prompt = f"""You are evaluating an AI firewall management system's response to a user question.

USER QUESTION:
{question}

AI SYSTEM RESPONSE:
{response}

EXPECTED INFORMATION:
{json.dumps(expected_info, indent=2)}

EVALUATION CRITERIA:
{criteria}

Evaluate the response and provide:
1. PASS/FAIL - Does the response adequately answer the question?
2. SCORE (0-100) - How complete and accurate is the response?
3. REASONING - Why did you give this score?
4. MISSING_INFO - What expected information is missing (if any)?

Respond in JSON format:
{{
    "pass": true/false,
    "score": 0-100,
    "reasoning": "explanation",
    "missing_info": ["item1", "item2"]
}}

Be strict but fair. The response should:
- Directly answer the question
- Include relevant data/metrics
- Be factually consistent
- Not hallucinate information

If the system says "no data" or "none found", that's acceptable IF it's a clear answer.
"""
        
        try:
            completion = self.client.chat.completions.create(
                model="gpt-4o-mini",  # Cheaper model for evaluation
                messages=[
                    {"role": "system", "content": "You are an expert evaluator of AI system responses. Be objective and thorough."},
                    {"role": "user", "content": evaluation_prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(completion.choices[0].message.content)
            return result
            
        except Exception as e:
            return {
                "pass": False,
                "score": 0,
                "reasoning": f"Evaluation failed: {str(e)}",
                "missing_info": []
            }


def check_server_running(url: str, timeout: int = 5) -> bool:
    """Check if HQ server is running"""
    try:
        response = requests.get(f"{url}/status", timeout=timeout)
        return response.status_code == 200
    except:
        return False


def wait_for_server(url: str, max_wait: int = 300):
    """Wait for user to start the HQ server"""
    print("=" * 100)
    print("🚀 HQ SERVER REQUIRED")
    print("=" * 100)
    print(f"\n⚠️  This test requires the HQ server to be running.")
    print(f"\n📋 To start the server, open a NEW terminal and run:")
    print(f"   cd {os.getcwd()}")
    print(f"   python hq/http_server.py")
    print(f"\n🔍 Checking if server is already running at {url}...")

    if check_server_running(url):
        print(f"✅ Server is already running!")
        return True

    print(f"\n❌ Server is not running yet.")
    print(f"\n⏳ Waiting for you to start the server...")
    print(f"   (Will check every 2 seconds for up to {max_wait} seconds)")
    print(f"\n   Press Ctrl+C to cancel")

    start_time = time.time()
    dots = 0

    try:
        while time.time() - start_time < max_wait:
            time.sleep(2)
            dots = (dots + 1) % 4
            print(f"\r   Checking{'.' * dots}{' ' * (3 - dots)}", end='', flush=True)

            if check_server_running(url):
                print(f"\n\n✅ Server detected! Starting tests...\n")
                time.sleep(1)  # Give server a moment to fully initialize
                return True

        print(f"\n\n❌ Timeout: Server did not start within {max_wait} seconds")
        print(f"   Please start the server and run the test again.")
        return False

    except KeyboardInterrupt:
        print(f"\n\n❌ Cancelled by user")
        return False


async def run_test_suite():
    """Run all test questions and evaluate responses"""

    print("=" * 100)
    print("🧪 AI CONSOLE Q&A TEST SUITE")
    print("=" * 100)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total questions: {len(TEST_QUESTIONS)}")
    print("=" * 100)

    # Wait for server to be running
    if not wait_for_server(HQ_SERVER_URL):
        print("\n❌ Cannot proceed without HQ server. Exiting.")
        return None

    # Initialize AI Command Center
    db_path = "hq_database.db"
    openai_api_key = os.getenv("OPENAI_API_KEY")

    if not openai_api_key:
        print("❌ ERROR: OPENAI_API_KEY not found in .env")
        return None

    print(f"\n{'=' * 100}")
    print("🤖 Initializing AI Command Center...")
    print(f"{'=' * 100}")
    ai_center = AICommandCenter(hq_url=HQ_SERVER_URL, openai_api_key=openai_api_key, db_path=db_path)
    print("✅ AI Command Center initialized")
    evaluator = AIEvaluator(api_key=openai_api_key)

    # Get client_id for opus-1
    client_id = "8cbb62eecbb00579"  # opus-1
    client_name = "opus-1"

    # Results tracking
    results = []
    passed = 0
    failed = 0
    total_score = 0

    # Run each test question
    for test in TEST_QUESTIONS:
        print(f"\n{'=' * 100}")
        print(f"📝 TEST #{test['id']}: {test['category']}")
        print(f"{'=' * 100}")
        print(f"Question: {test['question']}")
        print(f"\n⏳ Querying AI Console...")

        try:
            # Query the AI Console
            # Prepend client_id to question for context
            full_question = f"{test['question']} (client: {client_name})"

            start_time = datetime.now()
            response = await ai_center.chat_with_ai(full_question)
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()

            print(f"✅ Response received ({response_time:.2f}s)")
            print(f"\n{'─' * 100}")
            print("AI CONSOLE RESPONSE:")
            print(f"{'─' * 100}")
            print(response)
            print(f"{'─' * 100}")

            # Evaluate the response
            print(f"\n🤖 Evaluating response with AI...")
            evaluation = evaluator.evaluate_response(
                question=test['question'],
                response=response,
                expected_info=test['expected_info'],
                criteria=test['evaluation_criteria']
            )

            # Display evaluation
            status = "✅ PASS" if evaluation['pass'] else "❌ FAIL"
            print(f"\n{status}")
            print(f"Score: {evaluation['score']}/100")
            print(f"Reasoning: {evaluation['reasoning']}")

            if evaluation['missing_info']:
                print(f"Missing info: {', '.join(evaluation['missing_info'])}")

            # Track results
            result = {
                "test_id": test['id'],
                "category": test['category'],
                "question": test['question'],
                "response": response,
                "response_time_seconds": response_time,
                "evaluation": evaluation,
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)

            if evaluation['pass']:
                passed += 1
            else:
                failed += 1

            total_score += evaluation['score']

        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            result = {
                "test_id": test['id'],
                "category": test['category'],
                "question": test['question'],
                "response": None,
                "error": str(e),
                "evaluation": {
                    "pass": False,
                    "score": 0,
                    "reasoning": f"Test execution failed: {str(e)}",
                    "missing_info": []
                },
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
            failed += 1

    # Final summary
    print(f"\n{'=' * 100}")
    print("📊 TEST SUITE SUMMARY")
    print(f"{'=' * 100}")
    print(f"Total tests: {len(TEST_QUESTIONS)}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Average score: {total_score / len(TEST_QUESTIONS):.1f}/100")
    print(f"🎯 Pass rate: {(passed / len(TEST_QUESTIONS) * 100):.1f}%")

    # Category breakdown
    print(f"\n{'─' * 100}")
    print("RESULTS BY CATEGORY:")
    print(f"{'─' * 100}")

    categories = {}
    for result in results:
        cat = result['category']
        if cat not in categories:
            categories[cat] = {'passed': 0, 'failed': 0, 'scores': []}

        if result['evaluation']['pass']:
            categories[cat]['passed'] += 1
        else:
            categories[cat]['failed'] += 1
        categories[cat]['scores'].append(result['evaluation']['score'])

    for cat, stats in sorted(categories.items()):
        avg_score = sum(stats['scores']) / len(stats['scores'])
        status = "✅" if stats['failed'] == 0 else "⚠️"
        print(f"{status} {cat}: {stats['passed']}/{stats['passed'] + stats['failed']} passed (avg score: {avg_score:.1f})")

    # Save detailed results to JSON
    output_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "summary": {
                "total_tests": len(TEST_QUESTIONS),
                "passed": passed,
                "failed": failed,
                "average_score": total_score / len(TEST_QUESTIONS),
                "pass_rate": (passed / len(TEST_QUESTIONS) * 100),
                "timestamp": datetime.now().isoformat()
            },
            "results": results
        }, f, indent=2)

    print(f"\n{'=' * 100}")
    print(f"📄 Detailed results saved to: {output_file}")
    print(f"{'=' * 100}")

    return results


if __name__ == "__main__":
    asyncio.run(run_test_suite())
