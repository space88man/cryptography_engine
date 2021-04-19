import os
from cryptography_engine import engine
import subprocess


os.environ["SOFTHSM2_CONF"] = "tests/softhsm2.conf"
os.environ["OPENSSL_CONF"] = "tests/fixtures/openssl.cnf"

PIN = "userpin"
TOKEN = "MyToken1"
RSA_ALIAS = "RSA-0001"
EC_ALIAS = "EC-0003"

test_data = os.environ.get("TEST_ENGINE_DATA", None)
if test_data:
    TOKEN, PIN, RSA_ALIAS, EC_ALIAS = test_data.split()

RSA_PKCS11_URL = f"pkcs11:token={TOKEN};object={RSA_ALIAS}"
EC_PKCS11_URL = f"pkcs11:token={TOKEN};object={EC_ALIAS}"


class TestEngine:
    def test_engine_load(self):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])
        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        engine.engine_finish(e)

    def test_rsa_sign(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = b"\x00" * 8192
        p = tmp_path / "test_sign_data"
        p.write_bytes(data)

        for k in ("sha1", "sha256", "sha384", "sha512"):

            sig = pkey.sign(
                data, engine.engine_padding_pkcs1(), engine.engine_hashes(k)
            )
            assert len(sig) in (128, 256, 384, 512)

            p_sig = tmp_path / "test_sign_sig"
            p_sig.write_bytes(sig)

            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{k}",
                    "-engine",
                    "pkcs11",
                    "-keyform",
                    "engine",
                    "-verify",
                    alias,
                    "-signature",
                    f"{p_sig}",
                    f"{p}",
                ]
            )

            assert proc.returncode == 0

            pubkey.verify(
                sig, data, engine.engine_padding_pkcs1(), engine.engine_hashes(k)
            )

        engine.engine_finish(e)

    def test_pss_sign(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = b"\x00" * 8192
        p = tmp_path / "test_pss_sign_data"
        p.write_bytes(data)

        for k in ("sha256:222", "sha256:96", "sha384:206", "sha512:64"):

            k, saltlen = k.split(":")

            padding = engine.engine_padding_pss(k, int(saltlen))
            sig = pkey.sign(data, padding, engine.engine_hashes(k))
            assert len(sig) in (128, 256, 384, 512)

            p_sig = tmp_path / "test_pss_sign_sig"
            p_sig.write_bytes(sig)

            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{k}",
                    "-engine",
                    "pkcs11",
                    "-keyform",
                    "engine",
                    "-verify",
                    alias,
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-signature",
                    f"{p_sig}",
                    f"{p}",
                ]
            )

            assert proc.returncode == 0

            pubkey.verify(sig, data, padding, engine.engine_hashes(k))

        engine.engine_finish(e)

    def test_ec_sign(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = EC_PKCS11_URL
        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = b"\x00" * 8192
        p = tmp_path / "test_ec_sign_data"
        p.write_bytes(data)

        for k in ("sha256", "sha384", "sha512"):
            sig = pkey.sign(data, engine.ecdsa_with_hash(k))
            p_sig = tmp_path / "test_ec_sign_sig"
            p_sig.write_bytes(sig)

            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{k}",
                    "-engine",
                    "pkcs11",
                    "-keyform",
                    "engine",
                    "-verify",
                    alias,
                    "-signature",
                    f"{p_sig}",
                    f"{p}",
                ]
            )

            assert proc.returncode == 0

            pubkey.verify(sig, data, engine.ecdsa_with_hash(k))
        engine.engine_finish(e)

    def test_rsa_encrypt(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = os.urandom(128)
        p = tmp_path / "test_encrypt_data"
        p.write_bytes(data)

        padding = engine.engine_padding_pkcs1()
        out = pubkey.encrypt(data, padding)
        ciphered = tmp_path / "test_encrypt_ciphertext"
        ciphered.write_bytes(out)
        plaintext = tmp_path / "test_encrypt_plaintext"

        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-in",
                f"{ciphered}",
                "-out",
                f"{plaintext}",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-inkey",
                RSA_PKCS11_URL,
            ]
        )

        assert proc.returncode == 0
        recover = pkey.decrypt(out, padding)
        assert data == recover

        padding = engine.engine_padding_oaep("sha256", "sha256")
        out = pubkey.encrypt(data, padding)
        ciphered = tmp_path / "test_encrypt_cipheroaep"
        ciphered.write_bytes(out)
        plaintext = tmp_path / "test_encrypt_plainoaep"

        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-in",
                f"{ciphered}",
                "-out",
                f"{plaintext}",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-inkey",
                RSA_PKCS11_URL,
            ]
        )

        assert proc.returncode == 0
        recover = pkey.decrypt(out, padding)
        assert data == recover

        engine.engine_finish(e)

    def test_engine_sign(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = os.urandom(1048576)
        p = tmp_path / "test_sign_data"
        p.write_bytes(data)

        for k in ("sha256", "sha384", "sha512"):

            sig = engine.engine_sign(
                pkey._evp_pkey,
                data,
                algorithm=k,
                padding=(engine.RSAPadding.RSA_PKCS1_PADDING,),
            )
            assert len(sig) in (128, 256, 384, 512)

            p_sig = tmp_path / f"test_sign_sig-{k}"
            p_sig.write_bytes(sig)

            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{k}",
                    "-engine",
                    "pkcs11",
                    "-keyform",
                    "engine",
                    "-verify",
                    alias,
                    "-signature",
                    f"{p_sig}",
                    f"{p}",
                ]
            )

            assert proc.returncode == 0

            engine.engine_verify(
                pubkey._evp_pkey,
                sig,
                data,
                algorithm=k,
                padding=(engine.RSAPadding.RSA_PKCS1_PADDING,),
            )

        engine.engine_finish(e)

    def test_engine_pss_sign(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = os.urandom(1048576)
        p = tmp_path / "test_pss_sign_data"
        p.write_bytes(data)

        for k in ("sha256:64", "sha384:-1", "sha512:-2"):
            k, pss_saltlen = k.split(":")
            pss_saltlen = int(pss_saltlen)

            sig = engine.engine_sign(
                pkey._evp_pkey,
                data,
                algorithm=k,
                padding=(engine.RSAPadding.RSA_PKCS1_PSS_PADDING, pss_saltlen),
            )
            assert len(sig) in (128, 256, 384, 512)

            p_sig = tmp_path / f"test_pss_sign_sig-{k}"
            p_sig.write_bytes(sig)

            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{k}",
                    "-engine",
                    "pkcs11",
                    "-keyform",
                    "engine",
                    "-verify",
                    alias,
                    "-sigopt",
                    "rsa_padding_mode:pss",
                    "-signature",
                    f"{p_sig}",
                    f"{p}"
                ]
            )

            assert proc.returncode == 0

            engine.engine_verify(
                pubkey._evp_pkey,
                sig,
                data,
                algorithm=k,
                padding=(engine.RSAPadding.RSA_PKCS1_PSS_PADDING, pss_saltlen),
            )

        engine.engine_finish(e)

    def test_engine_encrypt(self, tmp_path):

        e = engine.engine_init("pkcs11", [("PIN", PIN)])

        alias = RSA_PKCS11_URL

        pkey = engine.engine_load_private_key(e, alias)
        pubkey = engine.engine_load_public_key(e, alias)

        data = os.urandom(128)
        p = tmp_path / "test_encrypt_data"
        p.write_bytes(data)

        out = engine.engine_encrypt(pubkey._evp_pkey, data, (1,))
        ciphered = tmp_path / "test_encrypt_ciphertext"
        ciphered.write_bytes(out)
        plaintext = tmp_path / "test_encrypt_plaintext"

        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-in",
                f"{ciphered}",
                "-out",
                f"{plaintext}",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-inkey",
                RSA_PKCS11_URL,
            ]
        )

        assert proc.returncode == 0
        recover = engine.engine_decrypt(
            pkey._evp_pkey, out, (engine.RSAPadding.RSA_PKCS1_PADDING,)
        )
        assert data == recover

        out = engine.engine_encrypt(
            pubkey._evp_pkey,
            data,
            padding=(engine.RSAPadding.RSA_PKCS1_OAEP_PADDING, "sha256", "sha256"),
        )
        ciphered = tmp_path / "test_encrypt_cipheroaep"
        ciphered.write_bytes(out)
        plaintext = tmp_path / "test_encrypt_plainoaep"

        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-in",
                f"{ciphered}",
                "-out",
                f"{plaintext}",
                "-engine",
                "pkcs11",
                "-keyform",
                "engine",
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-inkey",
                RSA_PKCS11_URL,
            ]
        )

        assert proc.returncode == 0
        recover = engine.engine_decrypt(
            pkey._evp_pkey,
            out,
            (engine.RSAPadding.RSA_PKCS1_OAEP_PADDING, "sha256", "sha256"),
        )
        assert data == recover

        engine.engine_finish(e)
