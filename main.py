from fastapi import FastAPI, Request, Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
import os
from datetime import datetime
import httpx

app = FastAPI()

PRIVATE_KEY_PEM = os.environ.get("FLOW_PRIVATE_KEY", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")


def decrypt_request(body: dict, private_key_pem: str):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    encrypted_aes_key = base64.b64decode(body["encrypted_aes_key"])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    iv = base64.b64decode(body["initial_vector"])
    encrypted_flow_data = base64.b64decode(body["encrypted_flow_data"])
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(iv, encrypted_flow_data, None)
    decrypted_body = json.loads(decrypted_data.decode('utf-8'))
    return decrypted_body, aes_key, iv


def encrypt_response(response_obj: dict, aes_key: bytes, iv: bytes):
    flipped_iv = bytes([b ^ 0xff for b in iv])
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(
        flipped_iv,
        json.dumps(response_obj).encode('utf-8'),
        None
    )
    return base64.b64encode(encrypted).decode('utf-8')


async def obtener_entradas_de_hoy():
    hoy = datetime.now().strftime("%Y-%m-%d")
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{SUPABASE_URL}/rest/v1/menu_diario",
            params={
                "fecha": f"eq.{hoy}",
                "activo": "eq.true",
                "select": "entrada1,entrada2,entrada3"
            },
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}"
            }
        )
        if response.status_code != 200:
            return None
        rows = response.json()
        return rows[0] if rows else None


@app.get("/")
@app.get("/health")
async def health_check():
    return {"status": "active"}


@app.post("/")
async def whatsapp_flow_endpoint(request: Request):
    try:
        body = await request.json()
        
        if "encrypted_flow_data" not in body:
            return {"status": "active"}
        
        decrypted_body, aes_key, iv = decrypt_request(body, PRIVATE_KEY_PEM)
        print(f"REQUEST: {json.dumps(decrypted_body)}")
        
        action = decrypted_body.get("action")
        flow_token = decrypted_body.get("flow_token", "")
        
        if action == "ping":
            encrypted = encrypt_response(
                {"data": {"status": "active"}, "flow_token": flow_token},
                aes_key, iv
            )
            return Response(content=encrypted, media_type="text/plain")
        
        menu = await obtener_entradas_de_hoy()
        
        if not menu:
            response_payload = {
                "screen": "ENTRADAS",
                "data": {
                    "entrada1_label": "😕 No hay entradas disponibles hoy",
                    "entrada2_label": "Vuelve a intentarlo mas tarde",
                    "entrada3_label": "-",
                },
                "flow_token": flow_token
            }
        else:
            response_payload = {
                "screen": "ENTRADAS",
                "data": {
                    "entrada1_label": f"🥣 {menu['entrada1']}",
                    "entrada2_label": f"🍮 {menu['entrada2']}",
                    "entrada3_label": f"🍎 {menu['entrada3']}",
                },
                "flow_token": flow_token
            }
        
        print(f"RESPONSE: {json.dumps(response_payload)}")
        
        encrypted = encrypt_response(response_payload, aes_key, iv)
        return Response(content=encrypted, media_type="text/plain")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return Response(
            content=json.dumps({"error": str(e)}),
            status_code=421,
            media_type="application/json"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
