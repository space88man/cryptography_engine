from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, )
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import (PKCS1v15, PSS,
                                                               MGF1, OAEP)

from cryptography.hazmat.backends.openssl.rsa import (_RSAPublicKey,
                                                      _RSAPrivateKey)
from cryptography.hazmat.backends.openssl.ec import (_EllipticCurvePublicKey,
                                                     _EllipticCurvePrivateKey)

import logging


class RSAPadding:
    RSA_PKCS1_PADDING = 1
    RSA_SSLV23_PADDING = 2
    RSA_NO_PADDING = 3
    RSA_PKCS1_OAEP_PADDING = 4
    RSA_X931_PADDING = 5
    RSA_PKCS1_PSS_PADDING = 6


LOG = logging.getLogger(__name__)

_backend = default_backend()

_lib, _ffi = _backend._lib, _backend._ffi

_hashes = {
    'sha1': _lib.EVP_sha1,
    'sha256': _lib.EVP_sha256,
    'sha384': _lib.EVP_sha384,
    'sha512': _lib.EVP_sha512
}


def _get_ctx(pkey):
    pkey_ctx = _lib.EVP_PKEY_CTX_new(pkey, _ffi.NULL)
    _backend.openssl_assert(pkey_ctx != _ffi.NULL)
    pkey_ctx = _ffi.gc(pkey_ctx, _lib.EVP_PKEY_CTX_free)
    return pkey_ctx


def _hash_data(hsh, data):
    digest = hashes.Hash(engine_hashes(hsh), _backend)
    digest.update(data)
    return digest.finalize()


class _EngineRSAPublicKey1(_RSAPublicKey):
    pass


class _EngineRSAPrivateKey1(_RSAPrivateKey):
    def private_numbers(self):
        raise ValueError('Not implemented for engine private keys')

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise ValueError('Not implemented for engine private keys')


class _EngineECPublicKey1(_EllipticCurvePublicKey):
    pass


class _EngineECPrivateKey1(_EllipticCurvePrivateKey):
    def private_numbers(self):
        raise ValueError('Not implemented for engine private keys')

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise ValueError('Not implemented for engine private keys')


def engine_init(engine, commands):

    _lib.ENGINE_load_builtin_engines()

    e = _lib.ENGINE_by_id(engine.encode('ascii'))
    if e == _ffi.NULL:
        raise ValueError(f'Could not load engine {engine}')

    for k in commands:
        r = _lib.ENGINE_ctrl_cmd_string(e, k[0].encode('ascii'),
                                        k[1].encode('ascii'), 0)
        if r != 1:
            raise ValueError(f"ENGINE failed at command {k}")

    r = _lib.ENGINE_init(e)
    if r != 1:
        _lib.ENGINE_free(e)
        raise ValueError("ENGINE initialization failed")
    _lib.ENGINE_free(e)
    return e


def engine_padding_pkcs1():
    return PKCS1v15()


def engine_padding_oaep(hsh1, hsh2, label=None):
    return OAEP(MGF1(engine_hashes(hsh1)), engine_hashes(hsh2), label)


def engine_padding_pss(hsh, saltlen):
    return PSS(MGF1(engine_hashes(hsh)), saltlen)


def engine_hashes(hsh):
    return getattr(hashes, hsh.upper())()


def ecdsa_with_hash(k):
    return ECDSA(engine_hashes(k))


def engine_finish(engine):

    r = _lib.ENGINE_finish(engine)
    assert r == 1
    # r = _lib.ENGINE_free(engine)
    # assert r == 1


def engine_load_private_key(e, alias):

    key = _lib.ENGINE_load_private_key(e, alias.encode('ascii'),
                                               _ffi.NULL, _ffi.NULL)
    if key == _ffi.NULL:
        raise ValueError(f"ENGINE failed to load private key {alias}")
    LOG.info('loaded _Engine private key %s', alias)
    typz = _lib.EVP_PKEY_id(key)
    if typz == 6:
        rsa_cdata = _lib.EVP_PKEY_get1_RSA(key)
        assert rsa_cdata != _ffi.NULL
        return _EngineRSAPrivateKey1(_backend, rsa_cdata, key)
    elif typz == 408:
        ec_key_cdata = _lib.EVP_PKEY_get1_EC_KEY(key)
        assert ec_key_cdata != _ffi.NULL
        return _EngineECPrivateKey1(_backend, ec_key_cdata, key)
    else:
        raise ValueError(f"Unknown OpenSSL key type: {typz}")


def engine_load_public_key(e, alias):

    key = _lib.ENGINE_load_public_key(e, alias.encode('ascii'),
                                             _ffi.NULL, _ffi.NULL)
    if key == _ffi.NULL:
        raise ValueError(f"ENGINE failed to load public key {alias}")
    LOG.info('loaded _Engine public key %s', alias)
    typz = _lib.EVP_PKEY_id(key)
    if typz == 6:
        rsa_cdata = _lib.EVP_PKEY_get1_RSA(key)
        assert rsa_cdata != _ffi.NULL
        return _EngineRSAPublicKey1(_backend, rsa_cdata, key)
    elif typz == 408:
        ec_key_cdata = _lib.EVP_PKEY_get1_EC_KEY(key)
        assert ec_key_cdata != _ffi.NULL
        return _EngineECPublicKey1(_backend, ec_key_cdata, key)
    else:
        raise ValueError(f"Unknown OpenSSL key type: {typz}")


def engine_sign(pkey, data, hash='sha256', padding=None):

    if hash.startswith('pre:'):
        hash = hash[4:]
    else:
        data = _hash_data(hash, data)

    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_sign_init(ctx)
    assert r == 1

    r = _lib.EVP_PKEY_CTX_set_signature_md(ctx, _hashes[hash.lower()]())
    assert r == 1

    label = 'ANON'
    typz = _lib.EVP_PKEY_id(pkey)
    if typz == 6:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, 1)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_PSS_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padding[1])
                assert r == 1
        label = 'RSA'
    elif typz == 408:
        label = 'EC'
    else:
        raise ValueError(f'Unknown key type {typz}')

    sig_len = _ffi.new('size_t *')
    sig_len[0] = 512
    sig_buf = _ffi.new('unsigned char[512]')
    _lib.EVP_PKEY_sign(ctx, sig_buf, sig_len, data, len(data))
    LOG.debug('%s signature size: %d', label, sig_len[0])

    return _ffi.buffer(sig_buf)[:sig_len[0]]


def engine_verify(pkey, signature, data, hash='sha256', padding=None):

    if hash.startswith('pre:'):
        hash = hash[4:]
    else:
        data = _hash_data(hash, data)

    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_verify_init(ctx)
    assert r == 1

    r = _lib.EVP_PKEY_CTX_set_signature_md(ctx, _hashes[hash.lower()]())
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = 'ANON'
    if typz == 6:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, 1)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_PSS_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padding[1])
                assert r == 1
        label = 'RSA'
    elif typz == 408:
        label = 'EC'
    else:
        raise ValueError(f'Unknown key type {typz}')

    r = _lib.EVP_PKEY_verify(ctx, signature, len(signature), data, len(data))

    return r == 1


def engine_encrypt(pkey, plaintext, padding=None):
    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_encrypt_init(ctx)
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = 'ANON'
    if typz == 6:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx,
                                                  RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_OAEP_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_mgf1_md(
                    ctx, _hashes[padding[1].lower()]())
                assert r == 1
                r = _lib.EVP_PKEY_CTX_set_rsa_oaep_md(
                    ctx, _hashes[padding[2].lower()]())
                assert r == 1
        label = 'RSA'
    else:
        raise ValueError(f'Unknown key type for encryption: {typz}')

    outlen = _ffi.new('size_t *')
    outlen[0] = 512
    out = _ffi.new('unsigned char[512]')

    r = _lib.EVP_PKEY_encrypt(ctx, out, outlen, plaintext, len(plaintext))
    assert r == 1

    return _ffi.buffer(out)[:outlen[0]]


def engine_decrypt(pkey, ciphertext, padding=None):
    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_decrypt_init(ctx)
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = 'ANON'
    if typz == 6:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx,
                                                  RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_OAEP_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_mgf1_md(
                    ctx, _hashes[padding[1].lower()]())
                assert r == 1
                r = _lib.EVP_PKEY_CTX_set_rsa_oaep_md(
                    ctx, _hashes[padding[2].lower()]())
                assert r == 1
        label = 'RSA'
    else:
        raise ValueError(f'Unknown key type for encryption: {typz}')

    outlen = _ffi.new('size_t *')
    outlen[0] = 512
    out = _ffi.new('unsigned char[512]')

    r = _lib.EVP_PKEY_decrypt(ctx, out, outlen, ciphertext, len(ciphertext))
    assert r == 1

    return _ffi.buffer(out)[:outlen[0]]
