
import os
import json
import urllib.request
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

if not API_KEY:
    print("ERROR: No se encontró GEMINI_API_KEY en el archivo .env")
    raise SystemExit(1)

url = (
    "https://generativelanguage.googleapis.com/v1beta/models?"
    + urllib.parse.urlencode({"key": API_KEY})
)

try:
    with urllib.request.urlopen(url, timeout=30) as response:
        datos = json.loads(response.read().decode("utf-8"))

    print("\n===== MODELOS DISPONIBLES =====\n")

    encontrados = 0

    for modelo in datos.get("models", []):
        metodos = modelo.get("supportedGenerationMethods", [])

        if "generateContent" in metodos:
            nombre = modelo.get("name", "")
            descripcion = modelo.get("displayName", "Sin descripción")

            print(f"Modelo: {nombre}")
            print(f"Nombre: {descripcion}")
            print("-" * 45)

            encontrados += 1

    print(f"\nTotal de modelos compatibles: {encontrados}")

except Exception as error:
    print(f"Error consultando Gemini: {error}")
