"""
Test suite for auth47 library
"""
import pytest
from datetime import datetime, timedelta
from auth47 import (
    Auth47Error,
    Auth47Verifier,
    create_callback_uri,
    validate_generate_uri_args,
    validate_challenge,
    validate_proof,
)


class TestAuth47Error:
    def test_error_creation(self):
        error = Auth47Error('test message')
        assert error.args[0] == 'test message'
        assert isinstance(error, Exception)


class TestCallbackUri:
    def test_valid_http(self):
        assert create_callback_uri('http://example.com') == 'http://example.com'

    def test_valid_https(self):
        assert create_callback_uri('https://example.com') == 'https://example.com'

    def test_valid_srbn(self):
        assert create_callback_uri('srbn://123aef4567890aef') == 'srbn://123aef4567890aef'

    def test_invalid_protocol(self):
        with pytest.raises(Auth47Error, match='invalid protocol for callback URI'):
            create_callback_uri('ftp://example.com')

    def test_with_hash(self):
        with pytest.raises(Auth47Error, match='hash is forbidden in callback URI'):
            create_callback_uri('http://example.com#hash')

    def test_with_query(self):
        with pytest.raises(Auth47Error, match='search params are forbidden in callback URI'):
            create_callback_uri('http://example.com?param=value')


class TestValidateGenerateUriArgs:
    def test_missing_nonce(self):
        with pytest.raises(Auth47Error, match='"nonce": missing'):
            validate_generate_uri_args({})

    def test_invalid_nonce(self):
        with pytest.raises(Auth47Error, match='"nonce": invalid'):
            validate_generate_uri_args({'nonce': 'invalid-nonce!'})

    def test_invalid_resource(self):
        with pytest.raises(Auth47Error, match='"resource": invalid'):
            validate_generate_uri_args({'nonce': 'validnonce', 'resource': ''})

    def test_expired_date(self):
        past_date = datetime.now() - timedelta(hours=1)
        with pytest.raises(Auth47Error, match='"expires": invalid'):
            validate_generate_uri_args({'nonce': 'validnonce', 'expires': past_date})

    def test_valid_args(self):
        future_date = datetime.now() + timedelta(hours=1)
        validate_generate_uri_args({'nonce': 'validnonce', 'expires': future_date})


class TestValidateChallenge:
    def test_valid_challenge(self):
        validate_challenge('auth47://aZrzsdfsfs343432sdf?r=srbn')

    def test_invalid_protocol(self):
        with pytest.raises(Auth47Error, match='"challenge": invalid protocol'):
            validate_challenge('auth48://aZrzsdfsfs343432sdf?r=srbn')

    def test_missing_resource(self):
        with pytest.raises(Auth47Error, match='"challenge": missing resource'):
            validate_challenge('auth47://aZrzsdfsfs343432sdf')

    def test_invalid_param_c(self):
        with pytest.raises(Auth47Error, match='"challenge": invalid param "c"'):
            validate_challenge('auth47://aZrzsdfsfs343432sdf?r=srbn&c=value')


class TestValidateProof:
    def test_missing_auth47_response(self):
        with pytest.raises(Auth47Error, match='"auth47_response": missing'):
            validate_proof({})

    def test_invalid_version(self):
        with pytest.raises(Auth47Error, match='"auth47_response": invalid'):
            validate_proof({'auth47_response': '2.0'})

    def test_missing_challenge(self):
        with pytest.raises(Auth47Error, match='"challenge": missing'):
            validate_proof({'auth47_response': '1.0'})

    def test_missing_signature(self):
        with pytest.raises(Auth47Error, match='"signature": missing'):
            validate_proof({
                'auth47_response': '1.0',
                'challenge': 'auth47://aZrzsdfsfs343432sdf?r=srbn'
            })

    def test_missing_nym_and_address(self):
        with pytest.raises(Auth47Error, match='"nym" or "address" missing'):
            validate_proof({
                'auth47_response': '1.0',
                'challenge': 'auth47://aZrzsdfsfs343432sdf?r=srbn',
                'signature': 'SGVsbG8gV29ybGQ='
            })

    def test_valid_proof_with_nym(self):
        validate_proof({
            'auth47_response': '1.0',
            'challenge': 'auth47://aZrzsdfsfs343432sdf?r=srbn',
            'signature': 'SGVsbG8gV29ybGQ=',
            'nym': 'PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA'
        })


class TestAuth47Verifier:
    def test_invalid_callback_uri(self):
        with pytest.raises(Auth47Error):
            Auth47Verifier('ftp://samourai.io')

    def test_generate_uri(self):
        verifier = Auth47Verifier('https://samourai.io')
        uri = verifier.generate_uri('testnonce123')
        assert uri.startswith('auth47://testnonce123?')
        assert 'c=https%3A%2F%2Fsamourai.io' in uri

    def test_generate_uri_with_resource(self):
        verifier = Auth47Verifier('https://samourai.io')
        uri = verifier.generate_uri('testnonce123', resource='srbn')
        assert 'r=srbn' in uri

    def test_generate_uri_with_expires(self):
        verifier = Auth47Verifier('https://samourai.io')
        future_time = int((datetime.now() + timedelta(days=1)).timestamp())
        uri = verifier.generate_uri('testnonce123', expires=future_time)
        assert f'e={future_time}' in uri

    def test_verify_proof_validation(self):
        verifier = Auth47Verifier('https://samourai.io')
        result = verifier.verify_proof({
            'auth47_response': '2.0',
            'challenge': 'auth47://test?r=srbn',
            'signature': 'test',
            'nym': 'test'
        })
        assert result['result'] == 'error'
        assert '"auth47_response": invalid' in result['error']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
