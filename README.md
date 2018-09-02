# cryptography_engine

A thin set of wrappers over OpenSSL Engine key operations based on
[pyca/cryptography](https://github.com/pyca/cryptography)

## Read Me First!

This package uses pyca/cryptography internal and hazmat objects so it
is dependent on the version of pyca/cryptography and will break if various
internal symbols disappear.

The tests use the [pkcs11](https://github.com/OpenSC/libp11) engine with
[SoftHSMv2 v2.3](https://github.com/opendnssec/SoftHSMv2).

The tests assume that there is a SoftHSMv2 token in `tmp/tokens`. You can either
copy from `tests/tokens` *OR* create a new one using the script `./test_tokens.sh`
if your version of SoftHSMv2 is not binary compatible with v2.3.

The tests call out to an external `openssl` binary using subprocess for verification.
Note that there is a OpenSSL configuration file in `tests/fixtures/openssl.cnf` that
provides the PIN (default value: userpin). 


```sh
## EITHER
$ cp -r tests/tokens tmp/

## OR

$ ./test_tokens.sh
+ export SOFTHSM2_CONF=tests/softhsm2.conf
+ SOFTHSM2_CONF=tests/softhsm2.conf
+ SOFTHSM2_SO=/usr/lib64/libsofthsm2.so
+ MY_USER_PIN=userpin
+ MY_SO_PIN=sopin
+ MY_LABEL=MyToken1
+ mkdir -p tmp/tokens
+ rm -rf tmp/tokens/*
+ softhsm2-util --init-token --slot 0 --label MyToken1 --pin userpin --so-pin sopin
The token has been initialized and is reassigned to slot 1116624427
++ pkcs11-tool --module /usr/lib64/libsofthsm2.so -L
++ grep 'Slot 0'
++ sed 's/.*ID //'
+ SLOTID=0x428e562b
+ pkcs11-tool --module /usr/lib64/libsofthsm2.so --slot 0x428e562b --login --pin userpin -k --key-type RSA:2048 -a RSA-0001 -d 0001
Key pair generated:
Private Key Object; RSA
  label:      RSA-0001
  ID:         0001
  Usage:      decrypt, sign, unwrap
Public Key Object; RSA 2048 bits
  label:      RSA-0001
  ID:         0001
  Usage:      encrypt, verify, wrap
+ pkcs11-tool --module /usr/lib64/libsofthsm2.so --slot 0x428e562b --login --pin userpin -k --key-type EC:secp384r1 -a EC-0003 -d 0003
Key pair generated:
Private Key Object; EC
  label:      EC-0003
  ID:         0003
  Usage:      decrypt, sign, unwrap, derive
Public Key Object; EC  EC_POINT 384 bits
  EC_POINT:   046104d8840668fd9bdc55db075ae37de3349f405d60e2749f91660271188ea485c2da367ad230499725218b4a43fab616141765d6b50535ee1b871916da1eaabfae3f15c883665fbcfb7a267dcabbef8577800cf5840bb77f490aec8ba4337ded16f1
  EC_PARAMS:  06052b81040022
  label:      EC-0003
  ID:         0003
  Usage:      encrypt, verify, wrap, derive

$ pip install -e .
$ pytest tests
======================== test session starts ========================
platform linux -- Python 3.6.6, pytest-3.6.3, py-1.5.4, pluggy-0.6.0
rootdir: /cryptography_engine, inifile:
collected 8 items

tests/test_engine.py ........                                 [100%]

===================== 8 passed in 0.87 seconds ======================
```

## Usage:

### Get OpenSSL ENGINE reference

```python
import cryptography_engine.engine as engine

# get an engine object

'''engine_init(<name_of_token>, <list of ENGINE_ctrl_cmd_string-tuples (cmd_name, arg)>
The ENGINE_ctrl_cmd_string tuples depend on the OpenSSL engine.
'''

e = engine.engine_init('pkcs11', [('PIN', my_token_pin)])
```

### Asymmetric Key Operations

These keys are cryptography key objects and can be used similarly.


```python
import cryptography_engine.engine as engine
e = engine.engine_init('pkcs11', ('PIN', my_token_pin))

# get a private key
'''engine_load_private_key(engine, label_of_private_key)'''
prvkey = engine.engine_load_private_key(e, alias)

# get a public key

'''engine_load_public_key(engine, label_of_public_key)'''
pubkey = engine.engine_load_public_key(e, alias)

```

#### Utility Functions

cryptography methods need arguments of hashes and padding; these utility
module-level functions simplify calling cryptography methods.

```python
# AsymmetricPadding instances
engine_padding_pkcs1() # gets a PKCS1v15 instance
engine_padding_oaep(mgf1_hash_name, oaep_md_name, label) # gets an OAEP instance
engine_padding_pss(hash_name, salt_length) # gets a PSS instance

# HashAlgorithm instances
engine_hashes(hash_name) # gets a HashAlgorithm instance

# EllipticCurveSignatureAlgorithm
ecdsa_with_hash(hash_name) # gets a ECDSA instance
```

#### Object-Oriented Interfaces

Use engine keys just like cryptography key objects:

```python
# RSA Signing/Verification
padding = engine.engine_padding_pkcs1() #IS-A AsymmetricPadding
algorithm = engine.engine_hashes('sha256') #IS-A HashAlgorithm
signature = prvkey.sign(data, padding, algorithm)

# raise InvalidSignature exception if verification fails
pubkey.verify(signature, data, padding, algorithm)

# RSA_PSS
padding = engine.engine_padding_pss('sha256', 32)
algorithm = engine.engine_hashes('sha256')
signature = prvkey.sign(data, padding, algorithm)
pubkey.verify(signature, data, padding, algorithm)

# EC Signing/Verification
algorithm = engine.ecdsa_with_hash('sha256')
signature = prvkey.sign(data, algorithm)
pubkey.verify(signature, data, algorithm)

# Encryption/Decryption
padding = engine.engine_padding_pkcs1()
ciphertext = pubkey.encrypt(plaintext, padding)
recoveredtext = prvkey.decrypt(ciphertext, padding)

padding = engine.engine_padding_oaep('sha256', 'sha256')
ciphertext = pubkey.encrypt(plaintext, padding)
recoveredtext = prvkey.decrypt(ciphertext, padding)
```

### Low-level Functions

These execute engine functions directly and don't use cryptography's object-oriented
interfaces. They use raw cffi `EVP_PKEY` objects such as the internal `_evp_pkey` attr
of `cryptography` OpenSSL-backed key objects.

For the low-level functions `algorithm` is the name of the hash("sha1", "sha256" etc)
and `padding` is a tuple consisting of an int and padding-specific options.

* `algorithm`: `hash_name: str #"sha1" "sha256" "sha384" "sha512"`
    prepended with `"pre:"` for pre-hashed data
* `padding`: tuple,:
    * PKCS1v15: `(1,)`
    * PSS: `(6, salt_length: int)`
    * OAEP: `(4, mgf1_md_name: str, oaep_md_name: str)`
    
#### Sign/Verify Data

```python
import cryptography_engine.engine as engine

# get a pubkey/prvkey from engine...
# using cffi EVP_PKEY* keys, so access _evp_pkey attr

signature = engine.engine_sign(prvkey._evp_pkey, data, "sha256", (1,))
signature = engine.engine_sign(prvkey._evp_pkey, data, "pre:sha256", (6, -1))
signature = engine.engine_sign(prvkey._evp_pkey, data, "sha384", (6, -2))
# -1 - OpenSSL special value - use hash length
# -2 - OpenSSL special value - maximal salt length

assert engine.engine_verify(pubkey._evp_pkey, signature, data, algorithm, padding)

# returns True/False if verification succeeds

# data/signature: bytes
#
# algorithm: str sha1|sha256|sha384|sha512
#     hash used for digesting data
#     prepend algorithm  with 'pre:' if data is prehashed like cryptography's Prehashed class
#     i.e., pre:sha1|pre:sha256|pre:sha384|pre:sha512
#
# padding: tuple
#     RSASSA_PKCS1v15: 1 == engine.RSAPadding.RSA_PKCS1_PADDING
#         (1, )
#     RSASS_PSS: 6 == engine.RSAPadding.RSA_PKCS1_PSS_PADDING
#         (6, 32)
#         (6, -1)
#         (6, -2)
```

#### Encryption/Decryption

```python
import cryptography_engine.engine as engine

# get a pubkey/prvkey from engine...
# using cffi EVP_PKEY* keys, so access _evp_pkey attr

# padding = (1, )
# or
# padding = (4, 'sha256', 'sha256')

ciphertext = engine.engine_encrypt(pubkey._evp_pkey, plaintext, padding)
recovered = engine.engine_decrypt(prvkey._evp_pkey, ciphertext, padding)
assert recovered == plaintext

# plaintext/ciphertext: bytes
#
# padding: tuple
#     RSAES_PKCS1v15: 1 == engine.RSAPadding.RSA_PKCS1_PADDING
#         (1, )
#
#     RSAES_OAEP: 4 == engine.RSAPadding.RSA_PKCS1_OAEP_PADDING
#         (4, 'sha256', 'sha256')
```
