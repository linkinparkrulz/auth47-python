# Auth47 Python Library

A Python implementation of the Auth47 protocol for authentication using Bitcoin payment codes and addresses.

## Installation

```bash
pip install auth47
```

For full functionality including Bitcoin message verification and BIP47 support:

```bash
pip install auth47[full]
```

## Requirements

- Python 3.8+

Optional dependencies for full functionality:

- `bitcoinlib` - For Bitcoin message verification
- `bip47` - For payment code (PayNym) support

## Usage

### Initialize a Verifier

```python
from auth47 import Auth47Verifier

# Initialize with HTTPS callback URI
verifier = Auth47Verifier('https://samourai.io/auth')

# Or with Soroban callback URI
verifier = Auth47Verifier('srbn://123aef4567890aef@samourai.onion')
```

### Generate an Auth47 URI

```python
import secrets

# Generate random nonce
nonce = secrets.token_hex(12)

# Generate URI
uri = verifier.generate_uri(nonce=nonce)
print(f'URI generated: {uri}')

# With optional resource
uri = verifier.generate_uri(
    nonce=nonce,
    resource='https://samourai.io/protected-resource'
)

# With expiry
from datetime import datetime, timedelta

expiry = datetime.now() + timedelta(hours=1)
uri = verifier.generate_uri(
    nonce=nonce,
    expires=expiry
)
```

### Verify a Proof

```python
proof = {
    'auth47_response': '1.0',
    'challenge': 'auth47://aerezerzerze23131d?r=https://samourai.io/auth',
    'nym': 'PM8TJTLJbPRGxSbc8EJ...',
    'signature': 'Hyn9En/w5I2LHR...'
}

# Verify the proof (default bitcoin mainnet)
result = verifier.verify_proof(proof)

if result['result'] == 'ok':
    print('Proof is valid')
    print(f"Authenticated nym: {result['data']['nym']}")
else:
    print(f"Verification failed: {result['error']}")

# Verify on testnet
result = verifier.verify_proof(proof, network='testnet')
```

### Verify Proof with Bitcoin Address

```python
proof_with_address = {
    'auth47_response': '1.0',
    'challenge': 'auth47://test123?r=https://example.com',
    'address': 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    'signature': 'H2xbF4...'
}

result = verifier.verify_proof(proof_with_address)
```

## API Reference

### Auth47Verifier

#### `__init__(callback_uri: str)`

Initialize the verifier with a callback URI.

- `callback_uri`: HTTPS, HTTP, SRBN, or SRBNS URI for callbacks

#### `generate_uri(nonce: str, resource: Optional[str] = None, expires: Optional[Union[int, datetime]] = None) -> str`

Generate an Auth47 URI.

- `nonce`: Secure random alphanumeric string
- `resource`: Optional resource identifier
- `expires`: Optional expiry as UNIX timestamp or datetime object
- Returns: Auth47 URI string

#### `verify_proof(proof: dict, network: Literal['bitcoin', 'testnet', 'regtest'] = 'bitcoin') -> VerifyResult`

Verify an Auth47 proof.

- `proof`: Dictionary containing the proof data
- `network`: Bitcoin network type (default: 'bitcoin')
- Returns: Dictionary with 'result' key ('ok' or 'error')

## Exceptions

### Auth47Error

Raised for validation errors and protocol violations.

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/auth47-python.git
cd auth47-python

# Install development dependencies
pip install -e ".[dev,full]"
```

### Run Tests

```bash
pytest tests/ -v --cov=auth47
```

### Code Formatting

```bash
black src/ tests/
```

### Type Checking

```bash
mypy src/
```

## License

LGPL-3.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [Auth47 Protocol Specification](https://github.com/Samourai-Wallet/auth47)
- [TypeScript Implementation](https://github.com/Samourai-Wallet/auth47)
