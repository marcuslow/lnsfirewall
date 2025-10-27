#!/usr/bin/env python3
"""
Create deployment package for client
Packages only essential files needed to run the HQ server and distribute to pfSense clients
"""

import os
import shutil
import zipfile
from datetime import datetime

def create_deployment_package():
    """Create a deployment package with essential files only"""
    
    # Package name with timestamp
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    package_name = f"lnsfirewall-deployment-{timestamp}"
    package_dir = os.path.join("deployment_packages", package_name)
    
    # Create package directory
    os.makedirs(package_dir, exist_ok=True)
    
    print(f"📦 Creating deployment package: {package_name}")
    print("=" * 60)
    
    # Essential directories to copy (entire folders)
    directories = [
        "hq",
        "client",
        "config",
    ]
    
    # Essential individual files
    files = [
        "requirements.txt",
        "distribute.py",
        "make_client_bundle.bat",
        "start_hq_server.bat",
        "setup_postgres_db.py",
        "README.md",
        "README.START.md",  # Will be created separately
        "GeoLite2-Country.mmdb",  # Optional but useful
    ]
    
    # Optional files (copy if they exist)
    optional_files = [
        "ngrok.yml",
        ".env.example",
    ]
    
    # Copy directories
    for dir_name in directories:
        if os.path.exists(dir_name):
            dest = os.path.join(package_dir, dir_name)
            print(f"📁 Copying directory: {dir_name}/")
            shutil.copytree(dir_name, dest, ignore=shutil.ignore_patterns(
                '__pycache__',
                '*.pyc',
                '*.pyo',
                '*.pyd',
                '.DS_Store',
                '*.so',
                '*.dylib',
            ))
    
    # Copy essential files
    for file_name in files:
        if os.path.exists(file_name):
            dest = os.path.join(package_dir, file_name)
            print(f"📄 Copying file: {file_name}")
            shutil.copy2(file_name, dest)
        else:
            if file_name != "README.START.md":  # We'll create this
                print(f"⚠️  Warning: {file_name} not found, skipping")
    
    # Copy optional files
    for file_name in optional_files:
        if os.path.exists(file_name):
            dest = os.path.join(package_dir, file_name)
            print(f"📄 Copying optional file: {file_name}")
            shutil.copy2(file_name, dest)
    
    # Copy dist folder if it exists (pre-built client bundles)
    if os.path.exists("dist"):
        dest = os.path.join(package_dir, "dist")
        print(f"📁 Copying dist/ folder with pre-built bundles")
        shutil.copytree("dist", dest, ignore=shutil.ignore_patterns(
            '__pycache__',
            '*.pyc',
        ))
    
    # Create .env.example if it doesn't exist
    env_example_path = os.path.join(package_dir, ".env.example")
    if not os.path.exists(env_example_path):
        print(f"📄 Creating .env.example template")
        with open(env_example_path, 'w') as f:
            f.write("""# OpenAI API Key (REQUIRED)
OPENAI_API_KEY=sk-your-openai-api-key-here

# Database Configuration
DB_TYPE=postgres
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=lnsfirewall
POSTGRES_USER=postgres
POSTGRES_PASSWORD=lnsFirewall2024!

# Optional: Geographic analysis (ipinfo.io - 50k requests/month free)
IPINFO_TOKEN=your_ipinfo_token_here

# Optional: Threat intelligence (AbuseIPDB - 1k requests/day free)
ABUSEIPDB_KEY=your_abuseipdb_key_here
""")
    
    print()
    print("=" * 60)
    print(f"✅ Deployment package created: {package_dir}")
    print()
    
    # Create ZIP file
    zip_path = f"{package_dir}.zip"
    print(f"📦 Creating ZIP archive: {zip_path}")
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            # Skip __pycache__ directories
            dirs[:] = [d for d in dirs if d != '__pycache__']
            
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, os.path.dirname(package_dir))
                zipf.write(file_path, arcname)
    
    # Get ZIP file size
    zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    
    print()
    print("=" * 60)
    print("🎉 DEPLOYMENT PACKAGE READY!")
    print("=" * 60)
    print(f"📦 Package: {zip_path}")
    print(f"📊 Size: {zip_size_mb:.2f} MB")
    print()
    print("📋 Next steps:")
    print("1. Send the ZIP file to your client")
    print("2. Client should extract and follow README.START.md")
    print("3. Client needs to:")
    print("   - Install Python 3.8+")
    print("   - Install PostgreSQL")
    print("   - Get OpenAI API key")
    print("   - Run setup steps in README.START.md")
    print()
    
    return zip_path

if __name__ == '__main__':
    try:
        zip_path = create_deployment_package()
        print(f"✅ Success! Package ready: {zip_path}")
    except Exception as e:
        print(f"❌ Error creating package: {e}")
        import traceback
        traceback.print_exc()

