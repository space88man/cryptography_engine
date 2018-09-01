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

These keys are cryptography objects; to use them with the low-level functions
(see [Low-level Functions](#low-level-functions))
access the raw `EVP_PKEY` object via the attr `_evp_pkey`.

```python
# get a private key

import cryptography_engine.engine as engine
e = engine.engine_init('pkcs11', ('PIN', my_token_pin))

'''engine_load_private_key(engine, label_of_private_key)'''
prvkey = engine.engine_load_private_key(e, alias)

# get a public key

'''engine_load_public_key(engine, label_of_public_key)'''
pubkey = engine.engine_load_public_key(e, alias)

```

#### Utility Functions

cryptography methods need arguments of hashes and padding; these utility
functions simplify calling cryptography methods.

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

These methods mimic the corresponding methods of cryptography key objects:

```python
# RSA Signing/Verification
padding = engine.engine_padding_pkcs1()
algorithm = engine.engine_hashes('sha256')
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
signature = prvkey.sign(data,  algorithm)
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

These execute engine operations directly and don't use cryptography's object-oriented
interfaces. They use raw `EVP_PKEY` objects.

`cryptography` key objects have an attribute `_evp_pkey` that is a useable `EVP_PKEY`.


#### Sign/Verify Data

```python
import cryptography_engine.engine as engine
signature = engine.engine_sign(prvkey._evp_pkey, data, algorithm, padding)

assert engine.engine_verify(pubkey._evp_pkey, signature, data, algorithm, padding)

# returns True/False if verification succeeds

# data/signature: bytes
# algorithm: str sha1|sha256|sha384|sha512
#     hash used for digesting data
#     prepend algorithm  with 'pre:' if data is already prehashed
#     i.e., pre:sha1|pre:sha256|pre:sha384|pre:sha512
# padding: tuple
#     RSASSA_PKCS1v15 (1,)  (1 == engine.RSAPadding.RSA_PKCS1_PADDING)
#         E.g.: (1, )
#     RSASS_PSS (6, salt_length) (6 == engine.RSAPadding.RSA_PKCS1_PSS_PADDING)
#         OpenSSL accepts the unconventional salt lengths:
#         * -1 (salt length = hash length)
#         * -2 (maximum salt length)
#         E.g. (6, 32)
```

#### Encryption/Decryption

```python
import cryptography_engine.engine as engine
ciphertext = engine.engine_encrypt(pubkey._evp_pkey, plaintext, padding)
recovered = engine.engine_decrypt(prvkey._evp_pkey, ciphertext, padding)
assert recovered == plaintext

# plaintext/ciphertext: bytes
# padding: tuple
#     RSAES_PKCS1v15 (1,)  (1 == engine.RSAPadding.RSA_PKCS1_PADDING)
#         E.g. (engine.RSAPadding.RSA_PKCS1_PADDING, )
#     RSASS_OAEP (4, mgf1_hash_name, hash_name) (4 == engine.RSAPadding.RSA_PKCS1_OAEP_PADDING)
#         mgf1_hash_name: str; hash used for MGF1_MD sha1|sha256|sha384|sha512
#         hash_name: str; hash used for OEAP_MD sha1|sha256|sha384|sha512
#         usually mgf1_hash_name == hash_name
#         E.g. (engine.RSAPadding.RSA_PKCS1_OAEP_PADDING, 'sha256', 'sha256')
```
