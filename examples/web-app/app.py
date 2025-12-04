"""
Auth47 Web App Example
A Flask application demonstrating Auth47 authentication.
Environment-aware: Works locally and on Heroku automatically.
"""
import os
import sys
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import qrcode
from io import BytesIO
import base64

# Add the parent src directory to Python path to import auth47
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from auth47 import Auth47Verifier, Auth47Error
except ImportError:
    print("Error: Could not import auth47. Make sure the library is properly installed.")
    sys.exit(1)

app = Flask(__name__)

# In-memory store for nonces (maps nonce -> session_id)
# In production, use Redis or a database
nonce_store = {}

# Environment-aware configuration
def get_environment_config():
    """Detect environment and return appropriate configuration."""
    # Check if we're on Heroku/Railway (PORT environment variable is set)
    if 'PORT' in os.environ:
        # Check for Railway-specific domain
        railway_domain = os.environ.get('RAILWAY_PUBLIC_DOMAIN')
        app_name = railway_domain if railway_domain else os.environ.get('HEROKU_APP_NAME', 'auth47-app')
        
        return {
            'environment': 'production',
            'debug': False,
            'host': '0.0.0.0',
            'port': int(os.environ.get('PORT', 5000)),
            'app_name': app_name,
            'secret_key': os.environ.get('SECRET_KEY', secrets.token_hex(32))
        }
    else:
        # Local development
        return {
            'environment': 'development',
            'debug': True,
            'host': '0.0.0.0',
            'port': 5000,
            'app_name': 'localhost:5000',
            'secret_key': os.environ.get('SECRET_KEY', secrets.token_hex(16))
        }

# Get configuration
config = get_environment_config()
app.secret_key = config['secret_key']

# Generate callback URL based on environment
if config['environment'] == 'production':
    # Remove .herokuapp.com if it's in the app_name
    base_domain = config['app_name'].replace('.herokuapp.com', '')
    CALLBACK_URL = f"https://{base_domain}/auth/callback"
else:
    CALLBACK_URL = f"http://{config['app_name']}/auth/callback"

# Initialize Auth47 verifier
verifier = Auth47Verifier(CALLBACK_URL)

# Print configuration on startup
def print_startup_info():
    """Print startup information."""
    print(f"🚀 Starting Auth47 Web App Example")
    print(f"🌍 Environment: {config['environment']}")
    print(f"📱 Callback URL: {CALLBACK_URL}")
    if config['environment'] == 'development':
        print(f"🌐 Open http://localhost:5000 in your browser")
    else:
        print(f"🌐 App URL: https://{config['app_name']}")
    print(f"📋 This app demonstrates Auth47 authentication flow")
    print("")

@app.route('/')
def index():
    """Home page with login option."""
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('protected'))
    return render_template('index.html')

@app.route('/login')
def login():
    """Generate Auth47 challenge for user to authenticate."""
    # Generate a secure random nonce
    nonce = secrets.token_hex(12)
    
    # Store nonce mapped to current session ID in our nonce store
    nonce_store[nonce] = {
        'session_id': session.sid if hasattr(session, 'sid') else secrets.token_hex(16),
        'timestamp': datetime.now()
    }
    
    # Also store in session for the browser
    session['auth_nonce'] = nonce
    
    # Generate Auth47 URI with expiry (15 minutes from now)
    expiry = datetime.now() + timedelta(minutes=15)
    
    # Create full absolute URL for the redirect resource
    if request.host.startswith('localhost'):
        redirect_url = f"http://{request.host}/protected"
    else:
        redirect_url = f"https://{request.host}/protected"
    
    auth_uri = verifier.generate_uri(
        nonce=nonce,
        resource=redirect_url,
        expires=expiry
    )
    
    # Generate QR code for the Auth47 URI
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(auth_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64 for display in HTML
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('login.html', 
                         auth_uri=auth_uri, 
                         qr_code=qr_base64,
                         expiry=expiry.strftime('%Y-%m-%d %H:%M:%S UTC'))

@app.route('/auth/callback', methods=['POST'])
def auth_callback():
    """Handle Auth47 proof verification."""
    try:
        # Get proof from request
        proof = request.get_json()
        if not proof:
            return jsonify({'error': 'No proof provided'}), 400
        
        if 'challenge' not in proof:
            return jsonify({'error': 'No challenge in proof'}), 400
        
        # Extract nonce from challenge
        from urllib.parse import urlparse
        parsed_challenge = urlparse(proof['challenge'])
        nonce = parsed_challenge.netloc
        
        # Check if nonce exists in our store
        if nonce not in nonce_store:
            return jsonify({'error': 'Invalid or expired nonce'}), 400
        
        # Get the stored session info for this nonce
        nonce_info = nonce_store[nonce]
        
        # Check if nonce is expired (15 minutes)
        if (datetime.now() - nonce_info['timestamp']).total_seconds() > 900:
            del nonce_store[nonce]
            return jsonify({'error': 'Authentication session expired'}), 400
        
        # Verify the proof
        result = verifier.verify_proof(proof)
        
        if result['result'] == 'ok':
            # Store authentication in a temporary store using nonce as key
            # This allows the browser to pick it up
            nonce_store[nonce]['authenticated'] = True
            nonce_store[nonce]['user_data'] = result['data']
            
            return jsonify({
                'success': True,
                'message': 'Authentication successful!',
                'nonce': nonce
            })
        else:
            return jsonify({'error': result['error']}), 400
            
    except Auth47Error as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 500

@app.route('/protected')
def protected():
    """Protected area only accessible after authentication."""
    if 'authenticated' not in session or not session['authenticated']:
        flash('Please authenticate to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user_data = session.get('user_data', {})
    return render_template('protected.html', user_data=user_data)

@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/api/status')
def api_status():
    """API endpoint to check authentication status."""
    # Check if we have a nonce in our session
    nonce = session.get('auth_nonce')
    
    if nonce and nonce in nonce_store:
        nonce_info = nonce_store[nonce]
        
        # Check if this nonce has been authenticated
        if nonce_info.get('authenticated'):
            # Transfer the authentication to the session
            session['authenticated'] = True
            session['user_data'] = nonce_info['user_data']
            
            # Clean up the nonce from store
            del nonce_store[nonce]
            
            return jsonify({
                'authenticated': True,
                'user_data': nonce_info['user_data']
            })
    
    return jsonify({
        'authenticated': session.get('authenticated', False),
        'user_data': session.get('user_data', {}) if session.get('authenticated') else None
    })

if __name__ == '__main__':
    print_startup_info()
    app.run(debug=config['debug'], host=config['host'], port=config['port'])