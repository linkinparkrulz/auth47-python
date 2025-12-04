# Auth47 Web App Example

A complete Flask web application demonstrating how to integrate Auth47 authentication into a web application.

## 🚀 Features

- **QR Code Authentication**: Mobile-friendly login using QR codes
- **Real-time Status**: Automatic authentication status checking
- **Protected Routes**: Access control for authenticated users
- **Session Management**: Secure session handling
- **Responsive Design**: Bootstrap-based UI that works on all devices
- **Error Handling**: Comprehensive error handling and user feedback

## 📋 Requirements

- Python 3.8+
- Flask 2.3.3+
- qrcode library
- Auth47 Python library (included in parent directory)

## 🛠️ Installation

1. **Navigate to the web app directory:**
   ```bash
   cd examples/web-app
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Open your browser:**
   Navigate to `http://localhost:5000`

## 🌐 Usage

### Basic Flow

1. **Home Page**: Visit the home page to learn about Auth47
2. **Login**: Click "Try Authentication" to start the login process
3. **Scan QR Code**: Use your Bitcoin wallet to scan the QR code
4. **Authenticate**: Sign the challenge in your wallet
5. **Access Protected Area**: Automatically redirected to protected content

### Manual Testing

Since this is a demonstration, you can also test the authentication flow manually:

1. **Generate Auth47 URI**: Visit `/login` to get a challenge
2. **Create Test Proof**: Use the test script or create a proof manually
3. **Submit Proof**: Send a POST request to `/auth/callback` with your proof

## 📁 Project Structure

```
examples/web-app/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   ├── base.html      # Base template with navigation
│   ├── index.html     # Home page
│   ├── login.html     # Login page with QR code
│   └── protected.html # Protected area for authenticated users
└── README.md          # This file
```

## 🔧 Configuration

### Callback URL

The application uses `http://localhost:5000/auth/callback` as the callback URL. 
In production, you should update this in `app.py`:

```python
CALLBACK_URL = "https://yourdomain.com/auth/callback"
```

### Session Security

The app uses a randomly generated secret key. In production, set a secure secret key:

```python
app.secret_key = "your-secure-secret-key-here"
```

## 📱 API Endpoints

### Web Routes

- `GET /` - Home page
- `GET /login` - Login page with QR code
- `POST /auth/callback` - Authentication callback endpoint
- `GET /protected` - Protected area (requires authentication)
- `GET /logout` - Logout and clear session

### API Routes

- `GET /api/status` - Check authentication status

### Authentication Flow

1. **Generate Challenge**: `GET /login`
   - Returns QR code and Auth47 URI
   - Stores nonce in session

2. **Verify Proof**: `POST /auth/callback`
   ```json
   {
     "auth47_response": "1.0",
     "challenge": "auth47://nonce?c=callback&r=resource",
     "signature": "base64-encoded-signature",
     "nym": "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
   }
   ```

3. **Check Status**: `GET /api/status`
   ```json
   {
     "authenticated": true,
     "user_data": {
       "auth47_response": "1.0",
       "challenge": "auth47://...",
       "signature": "...",
       "nym": "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
     }
   }
   ```

## 🧪 Testing

### Running the App

```bash
cd examples/web-app
python app.py
```

The app will start on `http://localhost:5000` with debug mode enabled.

### Test Authentication

Since this is a demonstration, you can test the authentication flow:

1. Visit `http://localhost:5000/login`
2. Copy the Auth47 URI displayed on the page
3. Use it with a Bitcoin wallet that supports Auth47
4. Or create a test proof using the Auth47 library

## 🔒 Security Considerations

### Development vs Production

- **Development**: Uses localhost callback URL and debug mode
- **Production**: Should use HTTPS and proper domain
- **Secret Key**: Use a secure, randomly generated secret key
- **Session Security**: Configure secure cookie settings in production

### Best Practices

1. **Use HTTPS** in production
2. **Set secure cookie flags**
3. **Use environment variables** for sensitive configuration
4. **Implement rate limiting** on authentication endpoints
5. **Log authentication attempts** for security monitoring

## 🚀 Deployment

### Docker (Recommended)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "app.py"]
```

### Traditional Deployment

1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables for production
3. Use a WSGI server like Gunicorn: `gunicorn app:app`
4. Configure reverse proxy (nginx/Apache) with SSL

## 🤝 Contributing

This is an example application. For contributing to the main Auth47 library, please refer to the parent directory.

## 📄 License

This example code follows the same license as the Auth47 Python library.

## 🔗 Related Links

- [Auth47 Protocol Specification](https://github.com/auth47/auth47-spec)
- [Auth47 Python Library](../../README.md)
- [Bitcoin Message Signing](https://en.bitcoin.it/wiki/Message_signing)
- [BIP47 Payment Codes](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki)

## 🆘 Troubleshooting

### Common Issues

1. **Import Error**: Make sure you're running from the correct directory
2. **QR Code Not Displaying**: Check that qrcode library is installed
3. **Authentication Fails**: Verify the callback URL matches your setup
4. **Session Issues**: Clear browser cookies and try again

### Debug Mode

The app runs in debug mode by default. Check the console output for detailed error messages.

### Getting Help

- Check the main Auth47 library documentation
- Review the Flask documentation for web app issues
- Open an issue for bugs or questions
