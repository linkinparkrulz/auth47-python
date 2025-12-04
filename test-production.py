#!/usr/bin/env python3
"""
Test script to verify production environment detection
"""
import os
import sys

# Set production environment variables
os.environ['PORT'] = '5000'
os.environ['HEROKU_APP_NAME'] = 'test-app'

# Add the parent src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and test the configuration
from examples.web-app.app import get_environment_config

config = get_environment_config()
print("🧪 Testing Production Environment Detection")
print(f"🌍 Environment: {config['environment']}")
print(f"📱 Debug Mode: {config['debug']}")
print(f"🌐 App Name: {config['app_name']}")
print(f"🔧 Port: {config['port']}")

if config['environment'] == 'production':
    print("✅ Production mode detected successfully!")
else:
    print("❌ Production mode not detected")
