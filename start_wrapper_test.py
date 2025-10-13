#!/usr/bin/env python3
"""
Startup script to run wrapper client and test workflow
"""

import asyncio
import subprocess
import sys
import time
import os

async def run_wrapper_and_test():
    """Run wrapper client and test workflow"""
    print("🚀 STARTING WRAPPER CLIENT AND TEST")
    print("=" * 60)
    
    # Start wrapper client in background
    print("1. Starting wrapper pfSense client...")
    wrapper_process = subprocess.Popen([
        sys.executable, "wrapper_pfsense_client.py", 
        "--client-id", "test-wrapper"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    print(f"   Wrapper client started (PID: {wrapper_process.pid})")
    print("   Waiting 5 seconds for client to connect...")
    await asyncio.sleep(5)
    
    try:
        # Check if wrapper is still running
        if wrapper_process.poll() is None:
            print("   ✅ Wrapper client is running")
        else:
            print("   ❌ Wrapper client exited early")
            stdout, stderr = wrapper_process.communicate()
            print(f"   STDOUT: {stdout}")
            print(f"   STDERR: {stderr}")
            return
        
        # Run the test
        print("\n2. Running workflow test...")
        test_process = subprocess.run([
            sys.executable, "test_wrapper_rule_push.py"
        ], capture_output=True, text=True)
        
        print("   Test output:")
        print(test_process.stdout)
        
        if test_process.stderr:
            print("   Test errors:")
            print(test_process.stderr)
        
        if test_process.returncode == 0:
            print("   ✅ Test completed successfully")
        else:
            print(f"   ❌ Test failed with return code {test_process.returncode}")
    
    finally:
        # Clean up wrapper process
        print("\n3. Cleaning up...")
        if wrapper_process.poll() is None:
            print("   Terminating wrapper client...")
            wrapper_process.terminate()
            try:
                wrapper_process.wait(timeout=5)
                print("   ✅ Wrapper client terminated")
            except subprocess.TimeoutExpired:
                print("   ⚠️  Force killing wrapper client...")
                wrapper_process.kill()
                wrapper_process.wait()

def run_manual_test():
    """Run manual test where user starts wrapper client separately"""
    print("🧪 MANUAL TEST MODE")
    print("=" * 60)
    print("This will test the wrapper client workflow manually.")
    print()
    print("Steps:")
    print("1. Open a new terminal/command prompt")
    print("2. Navigate to this directory")
    print("3. Run: python wrapper_pfsense_client.py --client-id test-wrapper")
    print("4. Wait for it to connect to the server")
    print("5. Come back here and press Enter")
    print()
    
    input("Press Enter when wrapper client is running and connected...")
    
    print("\nRunning test...")
    test_process = subprocess.run([
        sys.executable, "test_wrapper_rule_push.py"
    ], text=True)
    
    if test_process.returncode == 0:
        print("\n✅ Test completed successfully!")
    else:
        print(f"\n❌ Test failed with return code {test_process.returncode}")

def show_simulation_results():
    """Show the results in the simulation directory"""
    print("\n📁 SIMULATION RESULTS")
    print("=" * 60)
    
    sim_dir = os.path.join(os.getcwd(), "pfsense_simulation")
    
    if os.path.exists(sim_dir):
        print(f"Simulation directory: {sim_dir}")
        
        # Show config file
        config_file = os.path.join(sim_dir, "cf", "conf", "config.xml")
        if os.path.exists(config_file):
            print(f"\n📄 Config file: {config_file}")
            with open(config_file, 'r') as f:
                content = f.read()
            
            rule_count = content.count('<rule')
            print(f"   Rule count: {rule_count}")
            
            if "Test rule added by wrapper test" in content:
                print("   ✅ Test rule found in config!")
            else:
                print("   ⚠️  Test rule not found")
        
        # Show backups
        backup_dir = os.path.join(sim_dir, "backups")
        if os.path.exists(backup_dir):
            backups = [f for f in os.listdir(backup_dir) if f.startswith('config.xml.backup')]
            print(f"\n💾 Backup files ({len(backups)}):")
            for backup in sorted(backups)[-5:]:  # Show last 5
                backup_path = os.path.join(backup_dir, backup)
                backup_time = time.ctime(os.path.getmtime(backup_path))
                print(f"   {backup} ({backup_time})")
    else:
        print("❌ Simulation directory not found")

def main():
    """Main function"""
    print("🧪 WRAPPER CLIENT TEST RUNNER")
    print("=" * 60)
    print("Choose test mode:")
    print("1. Automatic (starts wrapper client automatically)")
    print("2. Manual (you start wrapper client separately)")
    print("3. Show simulation results only")
    print()
    
    choice = input("Enter choice (1/2/3): ").strip()
    
    if choice == "1":
        asyncio.run(run_wrapper_and_test())
    elif choice == "2":
        run_manual_test()
    elif choice == "3":
        show_simulation_results()
    else:
        print("Invalid choice")
        return
    
    # Always show results at the end
    if choice in ["1", "2"]:
        show_simulation_results()

if __name__ == "__main__":
    main()
