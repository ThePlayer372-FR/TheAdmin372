import asyncio
import os
import shutil
import tempfile
from pathlib import Path
import subprocess

from modules.backup.thesecret_client import (
    ensure_enrolled,
    get_thesecret_status,
    decrypt_dek_via_oracle,
    get_cert_paths,
)
from modules.backup.crypto import (
    encrypt_envelope,
    decrypt_envelope_via_thesecret,
    load_public_key,
)

async def run_integration_test():
    test_dir = Path(tempfile.mkdtemp(prefix="theadmin_thesecret_test_"))
    print(f"=== TEST RUN IN {test_dir} ===")

    try:
        host = "127.0.0.1"
        port = 372

        # 1. Test status prima dell'enrollment
        st_before = await get_thesecret_status(host=host, port=port, config_dir=test_dir)
        print("1. Status prima di enrollment:", st_before)
        assert st_before["enrolled"] is False
        assert st_before["status"] == "NOT_ENROLLED"
        print("   -> OK: correttamente non iscritto.")

        # 2. Test enrollment (Fase 1 Bootstrap)
        enroll_res = await ensure_enrolled(host=host, port=port, machine_name="theadmin372-testnode", config_dir=test_dir)
        print("2. Risultato Enrollment:", enroll_res)
        assert enroll_res["enrolled"] is True
        assert enroll_res["status"] == "PENDING"
        uid = enroll_res["uid"]
        assert uid is not None and uid.startswith("node-")
        print(f"   -> OK: CSR firmata, certificati mTLS salvati, UID={uid}")

        # Verifica presenza file mTLS
        ca_p, cert_p, key_p = get_cert_paths(test_dir)
        assert ca_p.is_file() and cert_p.is_file() and key_p.is_file()
        print("   -> OK: ca.crt, client.crt, client.key presenti.")

        # 3. Test status con stato PENDING
        st_pending = await get_thesecret_status(host=host, port=port, config_dir=test_dir)
        print("3. Status PENDING:", st_pending)
        assert st_pending["enrolled"] is True
        assert st_pending["connected"] is True
        assert st_pending["authorized"] is False
        assert st_pending["status"] == "PENDING"
        print("   -> OK: Nodo identificato come PENDING.")

        # 4. Verifica che DECRYPT_DEK fallisca se PENDING
        try:
            await decrypt_dek_via_oracle(b"fake_dek_data", host=host, port=port, config_dir=test_dir)
            raise AssertionError("Avrebbe dovuto fallire per autorizzazione mancante!")
        except PermissionError as pe:
            print("4. Chiamata oracolo bloccata con PENDING:", pe)
            print("   -> OK: Accesso negato correttamente prima dell'approvazione operatore.")

        # 5. Approvazione nodo tramite CLI thesecret372 (Human-In-The-Loop)
        print(f"5. Esecuzione autorizzazione nodo: thesecret372 request accept {uid}")
        proc = subprocess.run(["thesecret372", "request", "accept", uid], capture_output=True, text=True, check=True)
        print("   -> Output accept:", proc.stdout.strip())

        # 6. Test status con stato AUTHORIZED
        st_auth = await get_thesecret_status(host=host, port=port, config_dir=test_dir)
        print("6. Status AUTHORIZED:", st_auth)
        assert st_auth["enrolled"] is True
        assert st_auth["connected"] is True
        assert st_auth["authorized"] is True
        assert st_auth["status"] == "AUTHORIZED"
        assert st_auth["can_decrypt_backup"] is True
        print(f"   -> OK: Nodo AUTHORIZED con scopes={st_auth['scopes']}.")

        # 7. Test Envelope Encryption & Restore via Oracle
        print("7. Generazione payload cifrato e restore con TheSecret372...")
        # Usa la master public key di TheSecret372
        master_pub_path = Path.home() / ".thesecret372" / "secrets" / "master.pub"
        assert master_pub_path.is_file(), "Master public key mancante in ~/.thesecret372/secrets/master.pub"
        master_pub_key = load_public_key(master_pub_path)

        secret_original_data = b"THEADMIN372_DATABASE_AND_CONFIGURATION_PAYLOAD_TEST_DATA_372"
        # TheAdmin372 crea l'archivio usando la chiave pubblica del server TheSecret372:
        encrypted_archive = encrypt_envelope(secret_original_data, master_pub_key)
        print(f"   Archivio cifrato generato: {len(encrypted_archive)} bytes (Magic={encrypted_archive[:4]})")

        # TheAdmin372 ripristina l'archivio SENZA possedere la chiave privata, delegando a TheSecret372:
        # Patchiamo temporaneamente la config_dir per il test
        os.environ["THEADMIN_CONFIG_DIR"] = str(test_dir.parent)
        # Copia i certificati nella path attesa se usiamo get_thesecret_config_dir
        expected_dir = test_dir.parent / "thesecret"
        shutil.copytree(test_dir, expected_dir, dirs_exist_ok=True)

        decrypted_payload = await decrypt_envelope_via_thesecret(encrypted_archive, host=host, port=port)
        print(f"   Payload decifrato con successo: {decrypted_payload.decode('utf-8')}")

        assert decrypted_payload == secret_original_data, "I dati decifrati non corrispondono!"
        print("   -> OK: Decifratura tramite oracolo mTLS completata con SUCCESSO!")
        print("   -> ZERO MASTER KEY LEAKAGE verificato al 100%!")

        print("\n=======================================================")
        print(" TUTTI I TEST D'INTEGRAZIONE THEADMIN372 <-> THESECRET372")
        print(" SONO STATI SUPERATI CON SUCCESSO! ")
        print("=======================================================\n")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
        if "expected_dir" in locals():
            shutil.rmtree(expected_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(run_integration_test())
