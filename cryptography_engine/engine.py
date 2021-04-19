"""
Thin wrappers over OpenSSL ENGINE operations based on pyca/cryptography.
We try to make key objects behave like cryptography keys.
Provide low-level ENGINE functions that use the cffi directly.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, PSS, MGF1, OAEP

from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePublicKey,
    _EllipticCurvePrivateKey,
)

import logging
from typing import TypeVar, Union
from collections.abc import Sequence


ENGINE = TypeVar("ENGINE")
EVP_MD = TypeVar("EVP_MD")
EVP_PKEY = TypeVar("EVP_PKEY")
EVP_PKEY_CTX = TypeVar("EVP_PKEY_CTX")


class RSAPadding:
    RSA_PKCS1_PADDING = 1
    RSA_SSLV23_PADDING = 2
    RSA_NO_PADDING = 3
    RSA_PKCS1_OAEP_PADDING = 4
    RSA_X931_PADDING = 5
    RSA_PKCS1_PSS_PADDING = 6


# OpenSSL NIDs to identify key type from  EVP_PKEY*
# #define NID_rsaEncryption               6
# #define NID_X9_62_id_ecPublicKey      408
class _NID:
    RSA_ENCRYPTION = 6
    EC_PUBLIC_KEY = 408


LOG = logging.getLogger(__name__)

_backend = default_backend()

_lib, _ffi = _backend._lib, _backend._ffi


def _lib_hash(hsh: str) -> EVP_MD:
    # return getattr(_lib, 'EVP_' + hsh.lower())()
    return _lib.EVP_get_digestbyname(hsh.lower().encode("ascii"))


def _get_ctx(pkey):
    pkey_ctx = _lib.EVP_PKEY_CTX_new(pkey, _ffi.NULL)
    _backend.openssl_assert(pkey_ctx != _ffi.NULL)
    pkey_ctx = _ffi.gc(pkey_ctx, _lib.EVP_PKEY_CTX_free)
    return pkey_ctx


def _hash_data(hsh: str, data: bytes) -> bytes:
    digest = hashes.Hash(engine_hashes(hsh), _backend)
    digest.update(data)
    return digest.finalize()


class _EngineRSAPublicKey1(_RSAPublicKey):
    """wrapper for cryptography _RSAPublicKey class"""

    pass


class _EngineRSAPrivateKey1(_RSAPrivateKey):
    """wrapper for cryptography _RSAPrivateKey class
    We don't support serialization, unlike "soft" keys

    _RSAPrivateKey has changed its constructor to inspect the bytes
    of the "soft" key (RSA_check_key), so we copy-pasta here sans the
    check
    """

    def __init__(self, backend, rsa_cdata, evp_pkey):

        self._backend = backend
        self._rsa_cdata = rsa_cdata
        self._evp_pkey = evp_pkey

        n = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.RSA_get0_key(
            self._rsa_cdata,
            n,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
        )
        self._backend.openssl_assert(n[0] != self._backend._ffi.NULL)
        self._key_size = self._backend._lib.BN_num_bits(n[0])

    def private_numbers(self):
        raise ValueError("Not implemented for engine private keys")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise ValueError("Not implemented for engine private keys")


class _EngineECPublicKey1(_EllipticCurvePublicKey):
    """wrapper for cryptography _EllipticCurvePublicKey class"""

    pass


class _EngineECPrivateKey1(_EllipticCurvePrivateKey):
    """wrapper for cryptography _EllipticCurvePrivateKey class
    We don't support serialization, unlike "soft" keys
    """

    def private_numbers(self):
        raise ValueError("Not implemented for engine private keys")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise ValueError("Not implemented for engine private keys")


PrivateKey = Union[_EngineRSAPrivateKey1, _EngineECPrivateKey1]
PublicKey = Union[_EngineRSAPublicKey1, _EngineECPublicKey1]


def engine_init(engine: str, commands: Sequence[Sequence[str]]) -> ENGINE:
    """
    Create an engine object

    :param engine:
        str OpenSSL engine name

    :param commands:
        list of (str, str)-tuples representing OpenSSL's
        ENGINE_ctrl_cmd_string(cmd_name, arg) calls
        e.g., [('PIN', "super_secret_token-PIN")]

    :return:
        an ENGINE reference (cffi cdata type)
    """

    _lib.ENGINE_load_builtin_engines()

    e = _lib.ENGINE_by_id(engine.encode("ascii"))
    if e == _ffi.NULL:
        raise ValueError(f"Could not load engine {engine}")

    for k in commands:
        r = _lib.ENGINE_ctrl_cmd_string(
            e, k[0].encode("ascii"), k[1].encode("ascii"), 0
        )
        if r != 1:
            raise ValueError(f"ENGINE failed at command {k}")

    r = _lib.ENGINE_init(e)
    if r != 1:
        _lib.ENGINE_free(e)
        raise ValueError("ENGINE initialization failed")
    _lib.ENGINE_free(e)
    return e


def engine_padding_pkcs1() -> PKCS1v15:
    """
    Utility function for cryptography padding instance

    :return:
        PKCS1v15 instance
    """
    return PKCS1v15()


def engine_padding_oaep(hsh1: str, hsh2: str, label=None) -> OAEP:
    """
    Utility function for cryptography padding instance

    :param hsh1:
        str the hash name for MGF1_MD
        'sha1' 'sha256' etc
        OpenSSL EVP_PKEY_CTX_set_rsa_mgf1_md()

    :param hsh2:
        str the hash name for OAEP_MD
        'sha1' 'sha256' etc
        OpenSSL EVP_PKEY_CTX_set_rsa_oaep_md()

    :return:
        OAEP instance
    """
    return OAEP(MGF1(engine_hashes(hsh1)), engine_hashes(hsh2), label)


def engine_padding_pss(hsh: str, saltlen: int) -> PSS:
    """
    Utility function for cryptography padding instance

    :param hsh:
        str the hash name
        'sha1' 'sha256' etc
        OpenSSL EVP_PKEY_CTX_set_rsa_padding()

    :param saltlen:
        int the PSS salt length
        usually the hash length, e.g. 32 for sha256
        cannot use OpenSSL special -1, -2 values here
        OpenSSL EVP_PKEY_CTX_set_rsa_pss_saltlen()

    :return:
        PSS instance
    """
    return PSS(MGF1(engine_hashes(hsh)), saltlen)


def engine_hashes(hsh: str) -> hashes.HashAlgorithm:
    """
    Utility function for cryptography HashAlgorithm

    :param hsh:
        str the hash name
        'sha1' 'sha256', 'sha384' 'sha512'

    :return:
        HashAlgorithm instance
    """
    return getattr(hashes, hsh.upper())()


def ecdsa_with_hash(hsh: str) -> ECDSA:
    """
    Utility function for cryptography EllipticCurveSignatureAlgorithm instance

    :param k:
        str hash name

    :return:
        ECDSA instance
    """
    return ECDSA(engine_hashes(hsh))


def engine_finish(engine: ENGINE):
    """
    Clean up OpenSSL ENGINE

    :param engine:
        ENGINE reference

    """
    r = _lib.ENGINE_finish(engine)
    assert r == 1
    # r = _lib.ENGINE_free(engine)
    # assert r == 1


def engine_load_private_key(e: ENGINE, alias: str) -> PrivateKey:
    """
    Load a private key from an  OpenSSL ENGINE.

    :param e:
        ENGINE reference

    :param alias:
        str name of key

    :return:
        a cryptography *PrivateKey-like instance
        it should implement RSAPrivateKey/EllipticCurvePrivateKey
        this object does not support serialization
    """

    key = _lib.ENGINE_load_private_key(e, alias.encode("ascii"), _ffi.NULL, _ffi.NULL)
    if key == _ffi.NULL:
        raise ValueError(f"ENGINE failed to load private key {alias}")
    LOG.info("loaded _Engine private key %s", alias)
    typz = _lib.EVP_PKEY_id(key)
    if typz == _NID.RSA_ENCRYPTION:
        rsa_cdata = _lib.EVP_PKEY_get1_RSA(key)
        assert rsa_cdata != _ffi.NULL
        return _EngineRSAPrivateKey1(_backend, rsa_cdata, key)
    elif typz == _NID.EC_PUBLIC_KEY:
        ec_key_cdata = _lib.EVP_PKEY_get1_EC_KEY(key)
        assert ec_key_cdata != _ffi.NULL
        return _EngineECPrivateKey1(_backend, ec_key_cdata, key)
    else:
        raise ValueError(f"Unknown OpenSSL key type: {typz}")


def engine_load_public_key(e: ENGINE, alias: str) -> PublicKey:
    """
    Load a public key from an  OpenSSL ENGINE.

    :param e:
        ENGINE reference

    :param alias:
        str name of key

    :return:
        a cryptography *PublicKey-like instance
        it should implement RSAPublicKey/EllipticCurvePublicKey
    """

    key = _lib.ENGINE_load_public_key(e, alias.encode("ascii"), _ffi.NULL, _ffi.NULL)
    if key == _ffi.NULL:
        raise ValueError(f"ENGINE failed to load public key {alias}")
    LOG.info("loaded _Engine public key %s", alias)
    typz = _lib.EVP_PKEY_id(key)
    if typz == _NID.RSA_ENCRYPTION:
        rsa_cdata = _lib.EVP_PKEY_get1_RSA(key)
        assert rsa_cdata != _ffi.NULL
        return _EngineRSAPublicKey1(_backend, rsa_cdata, key)
    elif typz == _NID.EC_PUBLIC_KEY:
        ec_key_cdata = _lib.EVP_PKEY_get1_EC_KEY(key)
        assert ec_key_cdata != _ffi.NULL
        return _EngineECPublicKey1(_backend, ec_key_cdata, key)
    else:
        raise ValueError(f"Unknown OpenSSL key type: {typz}")


"""
OpenSSL exemplars:
openssl dgst -sha256 -engine pkcs11 -keyform engine
    -sign 'pkcs11:token=MyToken1;object=RSA-0001' \
    -out signature_file data_file

openssl dgst -sha256 -engine pkcs11 -keyform engine
    -sign 'pkcs11:token=MyToken1;object=RSA-0001' \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    -out signature_file data_file
"""


def engine_sign(
    pkey: PrivateKey, data: bytes, algorithm: str = "sha256", padding: tuple = None
) -> bytes:
    """
    Low-level ENGINE signing function

    :param pkey:
        EVP_PKEY signing private key; it is the _evp_pkey attribute
        of a cryptography key object

    :param data:
        bytes data to be signed

    :param algorithm:
        str name of hash, if data is prehashed then prepend with 'pre:'
        e.g. 'sha256' or 'pre:sha256'

    :param padding:
        tuple consisting of padding enum and options
        (1,) for PKCS1v15
        (6, salt_length) for PSS

    :return:
        bytes the signature value
    """

    if algorithm.startswith("pre:"):
        algorithm = algorithm[4:]
    else:
        data = _hash_data(algorithm, data)

    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_sign_init(ctx)
    assert r == 1

    r = _lib.EVP_PKEY_CTX_set_signature_md(ctx, _lib_hash(algorithm))
    assert r == 1

    label = "ANON"
    typz = _lib.EVP_PKEY_id(pkey)
    if typz == _NID.RSA_ENCRYPTION:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_PSS_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padding[1])
                assert r == 1
        label = "RSA"
    elif typz == _NID.EC_PUBLIC_KEY:
        label = "EC"
    else:
        raise ValueError(f"Unknown key type {typz}")

    sig_len = _ffi.new("size_t *")
    sig_len[0] = 512
    sig_buf = _ffi.new("unsigned char[512]")
    _lib.EVP_PKEY_sign(ctx, sig_buf, sig_len, data, len(data))
    LOG.debug("%s signature size: %d", label, sig_len[0])

    return _ffi.buffer(sig_buf)[: sig_len[0]]


"""
OpenSSL exemplars:
openssl dgst -sha256 -engine pkcs11 -keyform engine
    -verify 'pkcs11:token=MyToken1;object=RSA-0001' \
    -signature signature_file data_file

openssl dgst -sha256 -engine pkcs11 -keyform engine
    -verify 'pkcs11:token=MyToken1;object=RSA-0001' \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:32 \
    -signature signature_file data_file
"""


def engine_verify(
    pkey: PublicKey,
    signature: bytes,
    data: bytes,
    algorithm: str = "sha256",
    padding: tuple = None,
) -> bool:
    """
    Low-level ENGINE verification function

    :param pkey:
        EVP_PKEY verifiying public key; it is the _evp_pkey attribute
        of a cryptography key object

    :param signature:
        bytes signature

    :param data:
        bytes data to be verified

    :param algorithm:
        str name of hash, if data is prehashed then prepend with 'pre:'
        e.g. 'sha256' or 'pre:sha256'

    :param padding:
        tuple consisting of padding enum and options
        (1,) for PKCS1v15
        (6, salt_length) for PSS

    :return:
        True if verification is successful
    """

    if algorithm.startswith("pre:"):
        algorithm = algorithm[4:]
    else:
        data = _hash_data(algorithm, data)

    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_verify_init(ctx)
    assert r == 1

    r = _lib.EVP_PKEY_CTX_set_signature_md(ctx, _lib_hash(algorithm))
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = "ANON"
    if typz == _NID.RSA_ENCRYPTION:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_PSS_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, padding[1])
                assert r == 1
        label = "RSA"
    elif typz == _NID.EC_PUBLIC_KEY:
        label = "EC"
    else:
        raise ValueError(f"Unknown key type {typz}")

    r = _lib.EVP_PKEY_verify(ctx, signature, len(signature), data, len(data))

    return r == 1


"""
OpenSSL exemplars:
openssl pkeyutl -engine pkcs11 -keyform engine
    -inkey 'pkcs11:token=MyToken1;object=RSA-0001' \
    -encrypt -in plain_text -out cipher_text

openssl pkeyutl -engine pkcs11 -keyform engine
    -inkey 'pkcs11:token=MyToken1;object=RSA-0001' \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_mgf1_md:sha256 \
    -pkeyopt rsa_oaep_md:sha256 \
    -encrypt -in plain_text -out cipher_text
"""


def engine_encrypt(pkey: PrivateKey, plaintext: bytes, padding: tuple = None) -> bytes:
    """
    Low-level ENGINE encryption function

    :param pkey:
        EVP_PKEY encryption public key; it is the _evp_pkey attribute
        of a cryptography key object

    :param plaintext:
        bytes data to be encrypted

    :param padding:
        tuple consisting of padding enum and options
        (1,) for PKCS1v15
        (4, mgf1_md_name:str, oaep_md_name:str) for OAEP

    :return:
        bytes ciphertext
    """
    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_encrypt_init(ctx)
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = "ANON"
    if typz == _NID.RSA_ENCRYPTION:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_OAEP_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _lib_hash(padding[1]))
                assert r == 1
                r = _lib.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, _lib_hash(padding[2]))
                assert r == 1
        label = "RSA"
    else:
        raise ValueError(f"Unknown key type for encryption: {typz}")

    outlen = _ffi.new("size_t *")
    outlen[0] = 512
    out = _ffi.new("unsigned char[512]")

    r = _lib.EVP_PKEY_encrypt(ctx, out, outlen, plaintext, len(plaintext))
    assert r == 1

    return _ffi.buffer(out)[: outlen[0]]


"""
OpenSSL exemplars:
openssl pkeyutl -engine pkcs11 -keyform engine
    -inkey 'pkcs11:token=MyToken1;object=RSA-0001' \
    -decrypt -in cipher_text -out recovered_text

openssl pkeyutl -engine pkcs11 -keyform engine
    -inkey 'pkcs11:token=MyToken1;object=RSA-0001' \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_mgf1_md:sha256 \
    -pkeyopt rsa_oaep_md:sha256 \
    -decrypt -in cipher_text -out recovered_text
"""


def engine_decrypt(pkey: PrivateKey, ciphertext: bytes, padding: tuple = None) -> bytes:
    """
    Low-level ENGINE decryption function

    :param pkey:
        EVP_PKEY decryption private key; it is the _evp_pkey attribute
        of a cryptography key object

    :param ciphertext:
        bytes data to be decrypted

    :param padding:
        tuple consisting of padding enum and options
        (1,) for PKCS1v15
        (4, mgf1_md_name:str, oaep_md_name:str) for OAEP
        e.g., (4, 'sha256', 'sha256')

    :return:
        bytes plaintext
    """
    ctx = _get_ctx(pkey)

    r = _lib.EVP_PKEY_decrypt_init(ctx)
    assert r == 1

    typz = _lib.EVP_PKEY_id(pkey)
    label = "ANON"
    if typz == _NID.RSA_ENCRYPTION:  # RSA Key
        if not padding:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, RSAPadding.RSA_PKCS1_PADDING)
            assert r == 1
        else:
            r = _lib.EVP_PKEY_CTX_set_rsa_padding(ctx, padding[0])
            assert r == 1
            if padding[0] == RSAPadding.RSA_PKCS1_OAEP_PADDING:
                r = _lib.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, _lib_hash(padding[1]))
                assert r == 1
                r = _lib.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, _lib_hash(padding[2]))
                assert r == 1
        label = "RSA"
    else:
        raise ValueError(f"Unknown key type for encryption: {typz}")

    outlen = _ffi.new("size_t *")
    outlen[0] = 512
    out = _ffi.new("unsigned char[512]")

    r = _lib.EVP_PKEY_decrypt(ctx, out, outlen, ciphertext, len(ciphertext))
    assert r == 1

    return _ffi.buffer(out)[: outlen[0]]
