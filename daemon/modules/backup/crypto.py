import os
import struct
from pathlib import Path
from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"TA37"
VERSION = 0x01
NONCE_LEN = 12
GCM_TAG_LEN = 16


def generate_keypair(key_size: int = 4096) -> Tuple[bytes, bytes]:
    """
    Genera una coppia di chiavi RSA a 4096 bit in formato PEM (PKCS#8).
    Restituisce: (public_key_pem, private_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem, private_pem


def load_public_key(key_source: Union[str, Path, bytes]) -> rsa.RSAPublicKey:
    """Carica una chiave pubblica RSA da file path, stringa PEM o bytes PEM."""
    if isinstance(key_source, (str, Path)):
        p = Path(key_source)
        if p.is_file():
            pem_bytes = p.read_bytes()
        elif isinstance(key_source, str) and "-----BEGIN PUBLIC KEY-----" in key_source:
            pem_bytes = key_source.encode("utf-8")
        else:
            raise FileNotFoundError(f"File chiave pubblica non trovato in '{key_source}'")
    elif isinstance(key_source, bytes):
        pem_bytes = key_source
    else:
        raise TypeError("key_source deve essere str, Path o bytes")

    loaded = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise ValueError("La chiave fornita non è una chiave pubblica RSA valida")
    return loaded


def load_private_key(key_source: Union[str, Path, bytes], password: Union[bytes, None] = None) -> rsa.RSAPrivateKey:
    """Carica una chiave privata RSA da file path, stringa PEM o bytes PEM."""
    if isinstance(key_source, (str, Path)):
        p = Path(key_source)
        if p.is_file():
            pem_bytes = p.read_bytes()
        elif isinstance(key_source, str) and ("-----BEGIN PRIVATE KEY-----" in key_source or "-----BEGIN RSA PRIVATE KEY-----" in key_source):
            pem_bytes = key_source.encode("utf-8")
        else:
            raise FileNotFoundError(f"File chiave privata non trovato in '{key_source}'")
    elif isinstance(key_source, bytes):
        pem_bytes = key_source
    else:
        raise TypeError("key_source deve essere str, Path o bytes")

    loaded = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise ValueError("La chiave fornita non è una chiave privata RSA valida")
    return loaded


def encrypt_envelope(data_stream: bytes, pub_key: Union[rsa.RSAPublicKey, str, Path, bytes]) -> bytes:
    """
    Cifra i dati con Envelope Encryption ibrida:
    1. Genera una DEK AES-256 casuale (32 byte) e un nonce (12 byte).
    2. Cifra data_stream con AES-256-GCM ottenendo ciphertext e tag (16 byte).
    3. Cifra la DEK tramite RSA-OAEP (SHA-256 e MGF1 SHA-256) con la chiave pubblica.
    4. Confeziona il payload binario:
       [MAGIC:4B][VERSION:1B][RSA_KEY_LEN:2B][ENCRYPTED_DEK][NONCE:12B][GCM_TAG:16B][CIPHERTEXT]
    """
    if not isinstance(pub_key, rsa.RSAPublicKey):
        pub_key = load_public_key(pub_key)

    # 1. DEK da 256 bit e Nonce da 96 bit
    dek = os.urandom(32)
    nonce = os.urandom(NONCE_LEN)

    # 2. Cifratura simmetrica AES-256-GCM
    aesgcm = AESGCM(dek)
    # encrypt restituisce: ciphertext + tag (ultimi 16 byte)
    encrypted_payload = aesgcm.encrypt(nonce, data_stream, None)
    ciphertext = encrypted_payload[:-GCM_TAG_LEN]
    gcm_tag = encrypted_payload[-GCM_TAG_LEN:]

    # 3. Cifratura asimmetrica della DEK con RSA-OAEP
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    encrypted_dek = pub_key.encrypt(dek, oaep_padding)

    # 4. Composizione del file binario strutturato
    rsa_key_len = len(encrypted_dek)
    header = (
        MAGIC
        + bytes([VERSION])
        + struct.pack(">H", rsa_key_len)
        + encrypted_dek
        + nonce
        + gcm_tag
    )

    return header + ciphertext


def decrypt_envelope(enc_data: bytes, private_key_pem: Union[str, bytes, Path, rsa.RSAPrivateKey]) -> bytes:
    """
    Decifra un file generato da encrypt_envelope usando la chiave privata RSA:
    1. Verifica MAGIC e VERSION.
    2. Estrae ENCRYPTED_DEK, NONCE, GCM_TAG e CIPHERTEXT.
    3. Decifra la DEK tramite RSA-OAEP con la chiave privata.
    4. Decifra il CIPHERTEXT con AES-256-GCM verificando il GCM_TAG.
    """
    min_header_size = 4 + 1 + 2 + NONCE_LEN + GCM_TAG_LEN
    if len(enc_data) < min_header_size:
        raise ValueError("File archivio cifrato corrotto o dimensione insufficiente")

    magic = enc_data[:4]
    if magic != MAGIC:
        raise ValueError(f"Magic header non valido: atteso {MAGIC.decode(errors='replace')}, ricevuto {magic[:4]}")

    version = enc_data[4]
    if version != VERSION:
        raise ValueError(f"Versione envelope non supportata: {version}")

    rsa_key_len = struct.unpack(">H", enc_data[5:7])[0]
    offset = 7

    if len(enc_data) < offset + rsa_key_len + NONCE_LEN + GCM_TAG_LEN:
        raise ValueError("Intestazione dell'archivio incompleta o troncata")

    encrypted_dek = enc_data[offset : offset + rsa_key_len]
    offset += rsa_key_len

    nonce = enc_data[offset : offset + NONCE_LEN]
    offset += NONCE_LEN

    gcm_tag = enc_data[offset : offset + GCM_TAG_LEN]
    offset += GCM_TAG_LEN

    ciphertext = enc_data[offset:]

    # Carica la chiave privata
    if isinstance(private_key_pem, rsa.RSAPrivateKey):
        priv_key = private_key_pem
    else:
        priv_key = load_private_key(private_key_pem)

    # 1. Decifra la DEK
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    try:
        dek = priv_key.decrypt(encrypted_dek, oaep_padding)
    except Exception as e:
        raise ValueError(f"Decifratura DEK fallita: chiave privata errata o non corrispondente ({e})")

    # 2. Decifra il payload con AES-256-GCM
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + gcm_tag, None)
    except Exception as e:
        raise ValueError(f"Decifratura payload fallita: archivio manomesso o integrità compromessa ({e})")

    return plaintext
