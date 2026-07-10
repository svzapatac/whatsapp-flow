from fastapi import FastAPI, Request, Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
import os
import traceback
from datetime import datetime
import httpx

app = FastAPI()

# ─── CONFIGURACIÓN ───
PRIVATE_KEY_PEM = os.environ.get("FLOW_PRIVATE_KEY", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")


def decrypt_request(body: dict, private_key_pem: str):
    """Desencripta la petición de WhatsApp Flow."""

    # 1. Cargar clave privada RSA
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    # 2. Desencriptar la clave AES con RSA-OAEP
    encrypted_aes_key = base64.b64decode(body["encrypted_aes_key"])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Obtener IV y datos encriptados
    iv = base64.b64decode(body["initial_vector"])
    encrypted_flow_data = base64.b64decode(body["encrypted_flow_data"])

    # 4. Desencriptar con AES-GCM
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(iv, encrypted_flow_data, None)

    decrypted_body = json.loads(decrypted_data.decode('utf-8'))
    return decrypted_body, aes_key, iv


def encrypt_response(response_obj: dict, aes_key: bytes, iv: bytes):
    """Encripta la respuesta para WhatsApp Flow."""

    # Invertir el IV (XOR con 0xFF en cada byte) — requerido por Meta
    flipped_iv = bytes([b ^ 0xff for b in iv])

    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(
        flipped_iv,
        json.dumps(response_obj).encode('utf-8'),
        None
    )

    return base64.b64encode(encrypted).decode('utf-8')


def esta_disponible(valor_texto, flag_disponible):
    """
    Una entrada se considera disponible solo si:
    - el campo de texto no está vacío/null, Y
    - el flag manual de disponibilidad (si existe) no es False
    """
    texto_valido = bool(valor_texto) and str(valor_texto).strip() != ""
    flag_valido = flag_disponible if flag_disponible is not None else True
    return texto_valido and flag_valido


async def obtener_entradas_de_hoy():
    """Consulta el menú de hoy en Supabase."""
    hoy = datetime.now().strftime("%Y-%m-%d")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{SUPABASE_URL}/rest/v1/menu_diario",
            params={
                "fecha": f"eq.{hoy}",
                "activo": "eq.true",
                "select": "entrada1,entrada2,entrada3,entrada1_disponible,entrada2_disponible,entrada3_disponible"
            },
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}"
            }
        )

        if response.status_code != 200:
            print(f"SUPABASE ERROR: {response.status_code} - {response.text}")
            return None

        rows = response.json()
        return rows[0] if rows else None


@app.get("/")
async def health_check():
    return {"status": "active"}


@app.post("/")
async def whatsapp_flow_endpoint(request: Request):
    try:
        body = await request.json()

        # Si no hay datos encriptados, es un health check simple (GET-like ping externo)
        if "encrypted_flow_data" not in body:
            return {"status": "active"}

        # Desencriptar
        decrypted_body, aes_key, iv = decrypt_request(body, PRIVATE_KEY_PEM)
        print(f"REQUEST: {json.dumps(decrypted_body)}")

        action = decrypted_body.get("action")
        # Meta manda su propia versión en cada request; SIEMPRE debemos
        # reflejarla en la respuesta, no hardcodear "3.0".
        version = decrypted_body.get("version", "3.0")

        # Ping de salud que hace Meta periódicamente
        if action == "ping":
            encrypted = encrypt_response(
                {"data": {"status": "active"}},
                aes_key, iv
            )
            return Response(content=encrypted, media_type="text/plain")

        # Notificación de error del cliente (si tu respuesta anterior fue inválida)
        if action == "data_exchange" and decrypted_body.get("data", {}).get("error"):
            print(f"CLIENT ERROR NOTIFICATION: {decrypted_body}")

        # Obtener menú
        menu = await obtener_entradas_de_hoy()

        if not menu:
            response_payload = {
                "version": version,
                "screen": "ENTRADAS",
                "data": {
                    "entrada1_label": "😕 No hay entradas disponibles hoy",
                    "entrada2_label": "Vuelve a intentarlo mas tarde",
                    "entrada3_label": "-",
                    "entrada1_disponible": False,
                    "entrada2_disponible": False,
                    "entrada3_disponible": False,
                }
            }
        else:
            response_payload = {
                "version": version,
                "screen": "ENTRADAS",
                "data": {
                    "entrada1_label": f"🥣 {menu['entrada1']}" if menu.get('entrada1') else "-",
                    "entrada2_label": f"🍮 {menu['entrada2']}" if menu.get('entrada2') else "-",
                    "entrada3_label": f"🍎 {menu['entrada3']}" if menu.get('entrada3') else "-",
                    "entrada1_disponible": esta_disponible(menu.get('entrada1'), menu.get('entrada1_disponible')),
                    "entrada2_disponible": esta_disponible(menu.get('entrada2'), menu.get('entrada2_disponible')),
                    "entrada3_disponible": esta_disponible(menu.get('entrada3'), menu.get('entrada3_disponible')),
                }
            }

        print(f"RESPONSE: {json.dumps(response_payload)}")

        encrypted = encrypt_response(response_payload, aes_key, iv)
        return Response(content=encrypted, media_type="text/plain")

    except Exception as e:
        print(f"ERROR: {e}")
        print(traceback.format_exc())
        return Response(
            content=json.dumps({"error": str(e)}),
            status_code=421,
            media_type="application/json"
        )
