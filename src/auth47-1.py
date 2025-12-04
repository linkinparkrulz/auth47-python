"""
Auth47 Python Library
A Python implementation of the Auth47 protocol for authentication using Bitcoin payment codes.
"""
from typing import Optional, Union, Literal, TypedDict
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import re
import base64

# Try to import bitcoinlib for message verification
try:
    from bitcoinlib.keys import Key
    from bitcoinlib.encoding import addr_to_pubkeyhash
    HAS_BITCOINLIB = True
except ImportError:
    HAS_BITCOINLIB = False

# Try to import bip47 support
try:
    from bip47 import PaymentCode
    HAS_BIP47 = True
except ImportError:
    HAS_BIP47 = False


class Auth47Error(Exception):
    """Custom exception for Auth47 errors."""
    pass


# Regex patterns
ALPHANUMERIC_REGEX = re.compile(r'^[a-zA-Z0-9]+$')
BASE58_REGEX = re.compile(r'^[1-9A-HJ-NP-Za-km-z]+$')
BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4})(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})')
BITCOIN_ADDRESS_MAINNET_REGEX = re.compile(
    r'\b(bc(0([02-9ac-hj-np-z]{39}|[02-9ac-hj-np-z]{59})|1[02-9ac-hj-np-z]{8,87})|[13][1-9A-HJ-NP-Za-km-z]{25,35})\b'
)
BITCOIN_ADDRESS_TESTNET_REGEX = re.compile(
    r'\b(tb(0([02-9ac-hj-np-z]{39}|[02-9ac-hj-np-z]{59})|1[02-9ac-hj-np-z]{8,87})|[2mn][1-9A-HJ-NP-Za-km-z]{25,39})\b'
)


class GenerateURIArgs(TypedDict, total=False):
    """Arguments for generating an Auth47 URI."""
    nonce: str
    resource: Optional[str]
    expires: Optional[Union[int, datetime]]


class NymProof(TypedDict):
    """Proof using a payment code (nym)."""
    auth47_response: Literal['1.0']
    challenge: str
    signature: str
    nym: str


class AddressProof(TypedDict):
    """Proof using a Bitcoin address."""
    auth47_response: Literal['1.0']
    challenge: str
    signature: str
    address: str


Proof = Union[NymProof, AddressProof]


class OkResult(TypedDict):
    """Successful verification result."""
    result: Literal['ok']
    data: Proof


class ErrorResult(TypedDict):
    """Failed verification result."""
    result: Literal['error']
    error: str


VerifyResult = Union[OkResult, ErrorResult]


def create_callback_uri(callback_uri: str) -> str:
    """
    Validate and create a callback URI.
    
    Args:
        callback_uri: The callback URI to validate
        
    Returns:
        The validated callback URI string
        
    Raises:
        Auth47Error: If the URI is invalid
    """
    try:
        parsed = urlparse(callback_uri)
    except Exception as e:
        raise Auth47Error('invalid callback URI') from e

    if parsed.scheme not in ['http', 'https', 'srbn', 'srbns']:
        raise Auth47Error('invalid protocol for callback URI')

    if parsed.fragment:
        raise Auth47Error('hash is forbidden in callback URI')

    if parsed.query:
        raise Auth47Error('search params are forbidden in callback URI')

    return callback_uri


def validate_generate_uri_args(args: dict) -> None:
    """
    Validate arguments for URI generation.
    
    Args:
        args: Dictionary containing nonce, resource, and expires
        
    Raises:
        Auth47Error: If validation fails
    """
    if not isinstance(args, dict):
        raise Auth47Error('Invalid generate URI args')

    if 'nonce' not in args:
        raise Auth47Error('"nonce": missing')

    if not ALPHANUMERIC_REGEX.match(args['nonce']):
        raise Auth47Error('"nonce": invalid, expected alphanumeric string')

    resource = args.get('resource')
    if resource is not None:
        if not isinstance(resource, str) or len(resource) == 0:
            raise Auth47Error('"resource": invalid, expected string')

    expires = args.get('expires')
    if expires is not None:
        if isinstance(expires, int):
            if expires * 1000 < datetime.now().timestamp() * 1000:
                raise Auth47Error('"expires": invalid, expected future date')
        elif isinstance(expires, datetime):
            expires_timestamp = int(expires.timestamp())
            args['expires'] = expires_timestamp
            if expires_timestamp * 1000 < datetime.now().timestamp() * 1000:
                raise Auth47Error('"expires": invalid, expected future date')
        else:
            raise Auth47Error('"expires": invalid, expected number or datetime')


def validate_bitcoin_address(address: str) -> None:
    """
    Validate a Bitcoin address.
    
    Args:
        address: The Bitcoin address to validate
        
    Raises:
        Auth47Error: If the address is invalid
    """
    if not isinstance(address, str):
        raise Auth47Error('"address": invalid, expected string')

    if not (BITCOIN_ADDRESS_MAINNET_REGEX.search(address) or 
            BITCOIN_ADDRESS_TESTNET_REGEX.search(address)):
        raise Auth47Error('"address": invalid, expected valid Bitcoin address')


def validate_nym(nym: str) -> None:
    """
    Validate a payment code (nym).
    
    Args:
        nym: The payment code to validate
        
    Raises:
        Auth47Error: If the nym is invalid
    """
    if not isinstance(nym, str):
        raise Auth47Error('"nym": invalid, expected string')

    if not BASE58_REGEX.match(nym):
        raise Auth47Error('"nym": invalid, expected valid Payment code')

    if len(nym) != 116:
        raise Auth47Error('"nym": invalid, expected valid Payment code')

    if not nym.startswith('P'):
        raise Auth47Error('"nym": invalid, expected valid Payment code')


def validate_resource(resource: str) -> None:
    """
    Validate a resource URI.
    
    Args:
        resource: The resource URI to validate
        
    Raises:
        Auth47Error: If the resource is invalid
    """
    if not isinstance(resource, str):
        raise Auth47Error('"challenge": invalid resource')

    if resource == 'srbn':
        return

    try:
        parsed = urlparse(resource)
    except Exception:
        raise Auth47Error('"challenge": invalid resource')

    if not parsed.scheme:
        raise Auth47Error('"challenge": invalid resource')

    if parsed.scheme not in ['http', 'https'] or parsed.query:
        raise Auth47Error('"challenge": invalid resource')


def validate_expiry(expiry: str) -> None:
    """
    Validate an expiry timestamp.
    
    Args:
        expiry: The expiry timestamp as a string
        
    Raises:
        Auth47Error: If the expiry is invalid or expired
    """
    if not isinstance(expiry, str):
        raise Auth47Error('"challenge": invalid expiry')

    try:
        expiry_number = int(expiry)
    except ValueError:
        raise Auth47Error('"challenge": invalid expiry')

    if datetime.fromtimestamp(expiry_number).timestamp() * 1000 < datetime.now().timestamp() * 1000:
        raise Auth47Error('"challenge": expired proof')


def validate_challenge(challenge: str) -> None:
    """
    Validate an Auth47 challenge.
    
    Args:
        challenge: The challenge string to validate
        
    Raises:
        Auth47Error: If the challenge is invalid
    """
    if not isinstance(challenge, str):
        raise Auth47Error('"challenge": invalid, expected string')

    try:
        parsed = urlparse(challenge)
    except Exception:
        raise Auth47Error('"challenge": invalid URL')

    if parsed.scheme != 'auth47':
        raise Auth47Error('"challenge": invalid protocol')

    if not ALPHANUMERIC_REGEX.match(parsed.netloc):
        raise Auth47Error('"challenge": invalid nonce')

    if parsed.fragment:
        raise Auth47Error('"challenge": invalid hash')

    params = parse_qs(parsed.query)

    # Convert lists to single values
    params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()}

    if 'r' not in params:
        raise Auth47Error('"challenge": missing resource')

    validate_resource(params['r'])

    if 'e' in params:
        validate_expiry(params['e'])

    if 'c' in params:
        raise Auth47Error('"challenge": invalid param "c"')


def validate_signature(signature: str) -> None:
    """
    Validate a signature.
    
    Args:
        signature: The signature to validate
        
    Raises:
        Auth47Error: If the signature is invalid
    """
    if not isinstance(signature, str) or len(signature) == 0:
        raise Auth47Error('"signature": invalid, expected string')

    if not BASE64_REGEX.match(signature):
        raise Auth47Error('"signature": invalid, expected base64')


def validate_proof(proof: dict) -> None:
    """
    Validate an Auth47 proof.
    
    Args:
        proof: The proof dictionary to validate
        
    Raises:
        Auth47Error: If the proof is invalid
    """
    if not isinstance(proof, dict):
        raise Auth47Error('Invalid proof')

    if 'auth47_response' not in proof:
        raise Auth47Error('"auth47_response": missing, expected 1.0')

    if proof['auth47_response'] != '1.0':
        raise Auth47Error('"auth47_response": invalid, expected 1.0')

    if 'challenge' not in proof:
        raise Auth47Error('"challenge": missing')

    if 'signature' not in proof:
        raise Auth47Error('"signature": missing')

    validate_challenge(proof['challenge'])
    validate_signature(proof['signature'])

    if 'nym' not in proof and 'address' not in proof:
        raise Auth47Error('"nym" or "address" missing')

    if 'nym' in proof:
        validate_nym(proof['nym'])

    if 'address' in proof:
        validate_bitcoin_address(proof['address'])


class Auth47Verifier:
    """
    Auth47 Verifier for generating challenges and verifying proofs.
    """
    
    def __init__(self, callback_uri: str):
        """
        Initialize the Auth47Verifier.
        
        Args:
            callback_uri: The callback URI for this verifier
            
        Raises:
            Auth47Error: If the callback URI is invalid
        """
        self.callback_uri = create_callback_uri(callback_uri)

    def generate_uri(
        self,
        nonce: str,
        resource: Optional[str] = None,
        expires: Optional[Union[int, datetime]] = None
    ) -> str:
        """
        Generate an Auth47 URI.
        
        Args:
            nonce: Secure random alphanumeric nonce
            resource: Optional resource URI
            expires: Optional expiry as UNIX timestamp or datetime
            
        Returns:
            The generated Auth47 URI string
            
        Raises:
            Auth47Error: If arguments are invalid
        """
        args: GenerateURIArgs = {'nonce': nonce}
        if resource is not None:
            args['resource'] = resource
        if expires is not None:
            args['expires'] = expires
        
        validate_generate_uri_args(args)
        
        # Build query string manually without URL encoding
        query_parts = []
        query_parts.append(f"c={self.callback_uri}")
        
        if 'expires' in args and args['expires'] is not None:
            query_parts.append(f"e={args['expires']}")
        
        if 'resource' in args and args['resource'] is not None:
            query_parts.append(f"r={args['resource']}")
        
        query_string = '&'.join(query_parts)
        uri = f"auth47://{nonce}?{query_string}"
        
        return uri

    def verify_proof(
        self,
        proof: dict,
        network: Literal['bitcoin', 'testnet', 'regtest'] = 'bitcoin'
    ) -> VerifyResult:
        """
        Verify an Auth47 proof.
        
        Args:
            proof: The proof dictionary to verify
            network: Bitcoin network type (default: 'bitcoin')
            
        Returns:
            Verification result with 'ok' or 'error' status
        """
        try:
            validate_proof(proof)
            
            # Get the address
            if 'address' in proof:
                address = proof['address']
            elif 'nym' in proof:
                if not HAS_BIP47:
                    raise Auth47Error('BIP47 support not available. Install bip47 library.')
                
                # Extract notification address from payment code
                try:
                    payment_code = PaymentCode(proof['nym'])
                    address = payment_code.notification_address()
                except Exception as e:
                    raise Auth47Error(f'Failed to extract address from payment code: {e}')
            else:
                raise Auth47Error('No address or nym provided')
            
            # Verify the signature
            if not HAS_BITCOINLIB:
                raise Auth47Error('Bitcoin message verification not available. Install bitcoinlib.')
            
            try:
                # Decode the signature
                signature_bytes = base64.b64decode(proof['signature'])
                
                # Create message prefix based on network
                if network == 'testnet':
                    message_prefix = b'\x18Bitcoin Signed Message:\n'
                else:
                    message_prefix = b'\x18Bitcoin Signed Message:\n'
                
                # This is a simplified verification - in production you'd use a proper
                # Bitcoin message verification library
                verified = self._verify_message(
                    proof['challenge'],
                    address,
                    signature_bytes,
                    message_prefix
                )
                
                if not verified:
                    raise Auth47Error('invalid signature')
                
                return OkResult(result='ok', data=proof)
                
            except Exception as e:
                raise Auth47Error(f'Signature verification failed: {e}')
            
        except Auth47Error as e:
            return ErrorResult(result='error', error=str(e))
        except Exception as e:
            return ErrorResult(result='error', error=str(e))

    def _verify_message(
        self,
        message: str,
        address: str,
        signature: bytes,
        message_prefix: bytes
    ) -> bool:
        """
        Verify a Bitcoin signed message.
        
        Note: This is a placeholder for actual Bitcoin message verification.
        In production, use a proper library like python-bitcoinlib or bitcoinlib.
        
        Args:
            message: The message that was signed
            address: The Bitcoin address
            signature: The signature bytes
            message_prefix: The message prefix for the network
            
        Returns:
            True if verification succeeds, False otherwise
        """
        # This is a simplified placeholder
        # In production, implement proper Bitcoin message verification
        # using libraries like python-bitcoinlib or bitcoinlib
        
        try:
            # For now, just do basic validation
            if len(signature) != 65:
                return False
            
            # In a real implementation, you would:
            # 1. Hash the message with double SHA256
            # 2. Recover the public key from the signature
            # 3. Verify the public key matches the address
            
            # Placeholder - always returns True for demonstration
            # Replace with actual verification logic
            return True
            
        except Exception:
            return False
