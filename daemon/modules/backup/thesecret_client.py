import os
import ssl
import sys
import socket
import base64
import logging
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger("TheAdmin372.Backup.TheSecretClient")

MAX_PAYLOAD_SIZE = 64 * 1024


def get_thesecret_config_dir() -> Path:
    """Restituisce la directory di configurazione e certificati per TheSecret372."""
    config_base = os.getenv("THEADMIN_CONFIG_DIR")
    if config_base:
        target = Path(config_base) / "thesecret"
    else:
        target = Path("/etc/theadmin372/thesecret")

    try:
        target.mkdir(parents=True, exist_ok=True)
        return target
    except (PermissionError, OSError):
        user_fallback = Path.home() / ".theadmin372" / "thesecret"
        user_fallback.mkdir(parents=True, exist_ok=True)
        return user_fallback


def get_target_host_and_port(host: Optional[str] = None, port: Optional[int] = None) -> Tuple[str, int]:
    h = host or os.getenv("THESECRET_HOST", "127.0.0.1")
    p = port or int(os.getenv("THESECRET_PORT", "372"))
    return h, p


def get_cert_paths(config_dir: Optional[Path] = None) -> Tuple[Path, Path, Path]:
    cdir = config_dir or get_thesecret_config_dir()
    return cdir / "ca.crt", cdir / "client.crt", cdir / "client.key"


def is_enrolled(config_dir: Optional[Path] = None) -> bool:
    ca_crt, client_crt, client_key = get_cert_paths(config_dir)
    return ca_crt.is_file() and client_crt.is_file() and client_key.is_file()


def get_client_uid(client_crt_path: Optional[Path] = None) -> Optional[str]:
    """Estrae l'UID dal CommonName del certificato client x509."""
    if client_crt_path is None:
        _, client_crt_path, _ = get_cert_paths()
    if not client_crt_path.is_file():
        return None
    try:
        cert_data = client_crt_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception as e:
        logger.warning(f"Impossibile estrarre UID dal certificato {client_crt_path}: {e}")
    return None


async def _read_pem_block(reader: asyncio.StreamReader, end_marker: str = "-----END CERTIFICATE-----") -> bytes:
    lines: list[bytes] = []
    total_size = 0
    end_marker_bytes = end_marker.encode("utf-8")

    while True:
        line = await reader.readline()
        if not line:
            break
        total_size += len(line)
        if total_size > MAX_PAYLOAD_SIZE:
            raise ValueError("Dimensione blocco PEM eccede il limite di sicurezza")
        lines.append(line)
        if end_marker_bytes in line:
            break

    if not lines:
        raise ValueError("Nessun dato PEM valido ricevuto dal server")
    return b"".join(lines).strip()


def _generate_client_csr(machine_name: str) -> Tuple[bytes, bytes]:
    """Genera chiave privata client RSA a 2048 bit e la relativa CSR."""
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TheSecret372"),
                x509.NameAttribute(NameOID.COMMON_NAME, machine_name),
            ])
        )
        .sign(client_key, hashes.SHA256())
    )

    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return key_pem, csr_pem


async def ensure_enrolled(
    host: Optional[str] = None,
    port: Optional[int] = None,
    machine_name: Optional[str] = None,
    config_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Verifica la presenza dei certificati locali mTLS; se mancanti, avvia l'enrollment con TheSecret372."""
    cdir = config_dir or get_thesecret_config_dir()
    ca_crt, client_crt, client_key = get_cert_paths(cdir)

    if ca_crt.is_file() and client_crt.is_file() and client_key.is_file():
        uid = get_client_uid(client_crt)
        return {
            "enrolled": True,
            "uid": uid,
            "status": "ALREADY_ENROLLED",
            "message": f"Certificati mTLS già presenti per UID '{uid}'",
        }

    h, p = get_target_host_and_port(host, port)
    m_name = machine_name or socket.gethostname()
    logger.info(f"Avvio procedura di bootstrap & enrollment verso {h}:{p} per '{m_name}'...")

    # Connessione TLS anonima per la Fase 1 di bootstrap
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.open_connection(h, p, ssl=ctx)
    except Exception as e:
        raise ConnectionError(f"Impossibile raggiungere TheSecret372 su {h}:{p}: {e}")

    try:
        welcome = await reader.readline()
        welcome_txt = welcome.decode("utf-8", errors="replace").strip()
        logger.info(f"Handshake server TheSecret372: {welcome_txt}")

        # 1. Download Root CA
        if not ca_crt.is_file():
            writer.write(b"GET_CA\n")
            await writer.drain()
            ca_pem = await _read_pem_block(reader, end_marker="-----END CERTIFICATE-----")
            ca_crt.write_bytes(ca_pem)
            try:
                ca_crt.chmod(0o644)
            except OSError:
                pass
            logger.info(f"Certificato Root CA salvato in {ca_crt}")

        # 2. Generazione CSR e Richiesta di Firma
        key_pem, csr_pem = _generate_client_csr(m_name)
        client_key.write_bytes(key_pem.strip())
        try:
            client_key.chmod(0o600)
        except OSError:
            pass

        writer.write(f"REQ_SIGN {m_name}\n".encode("utf-8"))
        await writer.drain()

        ready_line = await reader.readline()
        if ready_line.strip() != b"READY":
            raise ValueError(f"Il server TheSecret372 non è pronto per la firma CSR: {ready_line.decode().strip()}")

        writer.write(csr_pem.strip() + b"\n")
        await writer.drain()

        signed_cert_pem = await _read_pem_block(reader, end_marker="-----END CERTIFICATE-----")
        client_crt.write_bytes(signed_cert_pem)
        try:
            client_crt.chmod(0o644)
        except OSError:
            pass

        writer.write(b"QUIT\n")
        await writer.drain()

        uid = get_client_uid(client_crt)
        logger.info(f"Certificato client ottenuto con successo. UID: {uid} (Stato su TheSecret372: PENDING)")

        return {
            "enrolled": True,
            "uid": uid,
            "machine_name": m_name,
            "status": "PENDING",
            "message": f"Enrollment completato. Il nodo '{uid}' è in attesa di autorizzazione.",
            "next_step": f"Esegui sul server TheSecret372: thesecret372 request accept {uid}",
        }

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _setup_mtls_context(config_dir: Optional[Path] = None) -> ssl.SSLContext:
    cdir = config_dir or get_thesecret_config_dir()
    ca_crt, client_crt, client_key = get_cert_paths(cdir)

    if not (ca_crt.is_file() and client_crt.is_file() and client_key.is_file()):
        raise FileNotFoundError(
            f"Certificati mTLS mancanti in {cdir}. Eseguire prima l'enrollment con TheSecret372."
        )

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_crt.resolve()))
    ssl_ctx.load_cert_chain(certfile=str(client_crt.resolve()), keyfile=str(client_key.resolve()))
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    return ssl_ctx


async def get_thesecret_status(
    host: Optional[str] = None,
    port: Optional[int] = None,
    config_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Interroga lo stato di connessione e autorizzazione con TheSecret372."""
    cdir = config_dir or get_thesecret_config_dir()
    ca_crt, client_crt, client_key = get_cert_paths(cdir)
    h, p = get_target_host_and_port(host, port)

    if not (ca_crt.is_file() and client_crt.is_file() and client_key.is_file()):
        return {
            "enrolled": False,
            "connected": False,
            "authorized": False,
            "status": "NOT_ENROLLED",
            "host": h,
            "port": p,
            "config_dir": str(cdir),
            "message": "Nessun certificato mTLS trovato. Eseguire 'theadmin372 thesecret enroll'.",
        }

    uid = get_client_uid(client_crt)
    ssl_ctx = _setup_mtls_context(cdir)

    try:
        reader, writer = await asyncio.open_connection(h, p, ssl=ssl_ctx)
    except ConnectionRefusedError:
        return {
            "enrolled": True,
            "connected": False,
            "authorized": False,
            "status": "UNREACHABLE",
            "uid": uid,
            "host": h,
            "port": p,
            "message": f"Server TheSecret372 non raggiungibile su {h}:{p}.",
        }
    except ssl.SSLError as e:
        return {
            "enrolled": True,
            "connected": False,
            "authorized": False,
            "status": "TLS_ERROR",
            "uid": uid,
            "host": h,
            "port": p,
            "message": f"Errore handshake TLS: {e}",
        }

    try:
        banner = await reader.readline()
        banner_txt = banner.decode("utf-8", errors="replace").strip()

        if banner_txt.startswith("ERROR PENDING_AUTHORIZATION:"):
            return {
                "enrolled": True,
                "connected": True,
                "authorized": False,
                "status": "PENDING",
                "uid": uid,
                "host": h,
                "port": p,
                "message": banner_txt,
                "next_step": f"Esegui sul server TheSecret372: thesecret372 request accept {uid}",
            }

        if not banner_txt.startswith("BENVENUTO"):
            return {
                "enrolled": True,
                "connected": True,
                "authorized": False,
                "status": "UNEXPECTED_BANNER",
                "uid": uid,
                "host": h,
                "port": p,
                "message": banner_txt,
            }

        # Connessione autorizzata: recupera identità e scopes con WHOAMI
        writer.write(b"WHOAMI\n")
        await writer.drain()

        whoami_res = await reader.readline()
        whoami_txt = whoami_res.decode("utf-8", errors="replace").strip()

        writer.write(b"QUIT\n")
        await writer.drain()

        scopes = []
        machine_name = "unknown"
        if whoami_txt.startswith("OK "):
            for part in whoami_txt[3:].split():
                if part.startswith("MACHINE="):
                    machine_name = part.split("=", 1)[1]
                elif part.startswith("SCOPES="):
                    scopes = [s for s in part.split("=", 1)[1].split(",") if s]

        has_decrypt = "backup:decrypt" in scopes
        return {
            "enrolled": True,
            "connected": True,
            "authorized": True,
            "status": "AUTHORIZED",
            "uid": uid,
            "machine_name": machine_name,
            "scopes": scopes,
            "can_decrypt_backup": has_decrypt,
            "host": h,
            "port": p,
            "message": f"Connesso e autorizzato. Scopes: {', '.join(scopes)}",
        }

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def decrypt_dek_via_oracle(
    encrypted_dek: bytes,
    host: Optional[str] = None,
    port: Optional[int] = None,
    config_dir: Optional[Path] = None,
) -> bytes:
    """
    Richiede all'oracolo TheSecret372 la decifratura della DEK tramite canale cifrato mTLS.
    Zero Master Key Leakage: la Master Private Key non lascia mai il server TheSecret372.
    """
    cdir = config_dir or get_thesecret_config_dir()
    if not is_enrolled(cdir):
        logger.info("Certificati mTLS assenti: avvio enrollment automatico...")
        await ensure_enrolled(host=host, port=port, config_dir=cdir)

    h, p = get_target_host_and_port(host, port)
    ssl_ctx = _setup_mtls_context(cdir)

    try:
        reader, writer = await asyncio.open_connection(h, p, ssl=ssl_ctx)
    except ConnectionRefusedError:
        raise ConnectionError(f"Impossibile connettersi all'oracolo TheSecret372 su {h}:{p}")
    except ssl.SSLError as e:
        raise PermissionError(f"Errore di negoziazione mTLS con TheSecret372: {e}")

    try:
        banner = await reader.readline()
        banner_txt = banner.decode("utf-8", errors="replace").strip()

        if banner_txt.startswith("ERROR PENDING_AUTHORIZATION:"):
            uid = get_client_uid(get_cert_paths(cdir)[1])
            raise PermissionError(
                f"Nodo non autorizzato su TheSecret372 ({banner_txt}). "
                f"Esegui sul server TheSecret372: thesecret372 request accept {uid}"
            )

        if not banner_txt.startswith("BENVENUTO"):
            raise RuntimeError(f"Messaggio iniziale inatteso da TheSecret372: {banner_txt}")

        # Invia DECRYPT_DEK <b64_enc_dek>
        enc_b64 = base64.b64encode(encrypted_dek).decode("utf-8")
        writer.write(f"DECRYPT_DEK {enc_b64}\n".encode("utf-8"))
        await writer.drain()

        response = await reader.readline()
        response_txt = response.decode("utf-8", errors="replace").strip()

        writer.write(b"QUIT\n")
        await writer.drain()

        if not response_txt.startswith("OK "):
            raise ValueError(f"Oracolo TheSecret372 ha rifiutato la decifratura: {response_txt}")

        raw_dek_b64 = response_txt[3:].strip()
        raw_dek = base64.b64decode(raw_dek_b64)
        return raw_dek

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def decrypt_dek_via_oracle_sync(
    encrypted_dek: bytes,
    host: Optional[str] = None,
    port: Optional[int] = None,
    config_dir: Optional[Path] = None,
) -> bytes:
    """Wrapper sincrono per invocare l'oracolo crittografico da contesti non-async."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Esecuzione in un thread worker dedicato se siamo già in un event loop
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                asyncio.run,
                decrypt_dek_via_oracle(encrypted_dek, host=host, port=port, config_dir=config_dir),
            )
            return future.result()
    else:
        return asyncio.run(
            decrypt_dek_via_oracle(encrypted_dek, host=host, port=port, config_dir=config_dir)
        )
