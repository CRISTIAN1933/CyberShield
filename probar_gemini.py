
import os
import json
import time
import urllib.request
import urllib.error
import urllib.parse

from datetime import datetime
from dotenv import load_dotenv

# ==========================================================
# CONFIGURACION
# ==========================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

TIMEOUT = 45

# Cantidad de intentos por modelo ante errores temporales
MAX_INTENTOS = 2

# Pausa entre modelos para evitar saturar la API
PAUSA_ENTRE_MODELOS = 1.5

MENSAJE_PRUEBA = """
Analiza este mensaje como especialista en ciberseguridad:

"Tu cuenta bancaria será bloqueada hoy.
Ingresa inmediatamente en este enlace para verificar tus datos."

Responde en español e indica:
1. Si es sospechoso.
2. Qué tipo de amenaza podría ser.
3. Qué indicadores de riesgo encontraste.
4. Qué recomendación darías al usuario.

Debes proporcionar una respuesta clara.
"""

# ==========================================================
# VALIDACIONES
# ==========================================================

if not API_KEY:
    print("ERROR: No se encontró GEMINI_API_KEY en .env")
    raise SystemExit(1)


# ==========================================================
# PETICION HTTP
# ==========================================================

def realizar_peticion(url, payload=None):

    headers = {}

    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET"
    )

    with urllib.request.urlopen(
        request,
        timeout=TIMEOUT
    ) as response:

        contenido = response.read().decode("utf-8")

        return json.loads(contenido)


# ==========================================================
# OBTENER MODELOS DISPONIBLES
# ==========================================================

def obtener_modelos():

    print("\nConsultando modelos disponibles...\n")

    url = (
        f"{BASE_URL}/models?"
        + urllib.parse.urlencode({"key": API_KEY})
    )

    try:

        datos = realizar_peticion(url)

        modelos = []

        for modelo in datos.get("models", []):

            metodos = modelo.get(
                "supportedGenerationMethods", []
            )

            if "generateContent" not in metodos:
                continue

            nombre = modelo.get("name", "")

            if not nombre:
                continue

            modelos.append({
                "id": nombre.replace("models/", ""),
                "nombre": modelo.get(
                    "displayName", nombre
                )
            })

        return modelos

    except urllib.error.HTTPError as error:

        print("ERROR consultando modelos:", error.code)
        print(error.read().decode("utf-8"))

    except Exception as error:

        print("ERROR:", error)

    return []


# ==========================================================
# PROBAR UN MODELO
# ==========================================================

def probar_modelo(modelo):

    nombre = modelo["id"]
    descripcion = modelo["nombre"]

    print("\n" + "=" * 65)
    print("PROBANDO:", descripcion)
    print("ID:", nombre)
    print("=" * 65)

    url = (
        f"{BASE_URL}/models/{nombre}:generateContent?"
        + urllib.parse.urlencode({"key": API_KEY})
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": MENSAJE_PRUEBA
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 500
        }
    }

    for intento in range(1, MAX_INTENTOS + 1):

        inicio = time.perf_counter()

        try:

            resultado = realizar_peticion(
                url,
                payload
            )

            duracion = time.perf_counter() - inicio

            candidatos = resultado.get("candidates", [])

            if not candidatos:
                raise ValueError(
                    "El modelo no devolvió candidatos."
                )

            partes = candidatos[0].get(
                "content", {}
            ).get("parts", [])

            respuesta = "".join(
                parte.get("text", "")
                for parte in partes
                if isinstance(parte.get("text"), str)
            ).strip()

            if not respuesta:
                raise ValueError(
                    "El modelo no devolvió texto utilizable."
                )

            print("\nRESULTADO: FUNCIONA")
            print(f"Tiempo: {duracion:.2f} segundos")
            print("\nRESPUESTA:")
            print(respuesta[:1200])

            return {
                "modelo": nombre,
                "nombre": descripcion,
                "estado": "FUNCIONA",
                "tiempo_segundos": round(duracion, 2),
                "intentos": intento,
                "respuesta": respuesta,
                "error": None
            }

        except urllib.error.HTTPError as error:

            codigo = error.code

            detalle = error.read().decode(
                "utf-8", errors="replace"
            )

            print(f"\nERROR HTTP: {codigo}")
            print(detalle[:500])

            # Reintentar errores temporales
            if codigo in (429, 500, 502, 503, 504):

                if intento < MAX_INTENTOS:

                    espera = 2 ** intento

                    print(
                        f"Reintentando en {espera} segundos..."
                    )

                    time.sleep(espera)
                    continue

            return {
                "modelo": nombre,
                "nombre": descripcion,
                "estado": "ERROR HTTP",
                "tiempo_segundos": None,
                "intentos": intento,
                "respuesta": None,
                "codigo_http": codigo,
                "error": detalle[:1000]
            }

        except Exception as error:

            print("\nERROR:", str(error))

            return {
                "modelo": nombre,
                "nombre": descripcion,
                "estado": "ERROR",
                "tiempo_segundos": None,
                "intentos": intento,
                "respuesta": None,
                "error": str(error)
            }

    return {
        "modelo": nombre,
        "nombre": descripcion,
        "estado": "ERROR",
        "tiempo_segundos": None,
        "respuesta": None,
        "error": "Se agotaron los intentos."
    }


# ==========================================================
# GUARDAR INFORME
# ==========================================================

def guardar_resultados(resultados):

    archivo = "resultados_modelos.json"

    informe = {
        "fecha": datetime.now().isoformat(),
        "total_modelos": len(resultados),
        "funcionan": sum(
            1 for r in resultados
            if r["estado"] == "FUNCIONA"
        ),
        "fallan": sum(
            1 for r in resultados
            if r["estado"] != "FUNCIONA"
        ),
        "resultados": resultados
    }

    with open(
        archivo,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            informe,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(f"\nInforme guardado en: {archivo}")


# ==========================================================
# RESUMEN FINAL
# ==========================================================

def mostrar_resumen(resultados):

    exitosos = [
        r for r in resultados
        if r["estado"] == "FUNCIONA"
    ]

    fallidos = [
        r for r in resultados
        if r["estado"] != "FUNCIONA"
    ]

    exitosos.sort(
        key=lambda r: r["tiempo_segundos"]
    )

    print("\n\n")
    print("#" * 75)
    print("             RESULTADO FINAL - CYBERSHIELD")
    print("#" * 75)

    print(f"\nModelos probados: {len(resultados)}")
    print(f"Modelos funcionales: {len(exitosos)}")
    print(f"Modelos con errores: {len(fallidos)}")

    print("\n" + "=" * 75)
    print("MODELOS QUE FUNCIONAN")
    print("=" * 75)

    for posicion, modelo in enumerate(exitosos, 1):

        print(
            f"{posicion}. {modelo['nombre']}"
        )

        print(
            f"   ID: {modelo['modelo']}"
        )

        print(
            f"   Tiempo: {modelo['tiempo_segundos']} segundos"
        )

    print("\n" + "=" * 75)
    print("MODELOS CON ERRORES")
    print("=" * 75)

    for modelo in fallidos:

        print(f"\n{modelo['nombre']}")
        print(f"ID: {modelo['modelo']}")
        print(f"Estado: {modelo['estado']}")

        if modelo.get("codigo_http"):
            print(f"HTTP: {modelo['codigo_http']}")

        print(f"Error: {modelo.get('error', 'Desconocido')[:250]}")

    print("\n" + "=" * 75)
    print("RECOMENDACION")
    print("=" * 75)

    if exitosos:

        mejor = exitosos[0]

        print("\nModelo más rápido que superó la prueba:")

        print("Nombre:", mejor["nombre"])
        print("ID:", mejor["modelo"])
        print(
            "Tiempo:",
            mejor["tiempo_segundos"],
            "segundos"
        )

        print("\nPara utilizarlo en tu .env:")

        print(
            f"GEMINI_MODEL={mejor['modelo']}"
        )

    else:

        print(
            "\nNingún modelo superó la prueba."
        )

        print(
            "Revisá la API Key, cuotas y errores HTTP."
        )

    print("\n" + "#" * 75)


# ==========================================================
# PROGRAMA PRINCIPAL
# ==========================================================

def main():

    print("\n")
    print("=" * 65)
    print("      CYBERSHIELD - EVALUADOR DE MODELOS GEMINI")
    print("=" * 65)

    modelos = obtener_modelos()

    if not modelos:

        print("\nNo se encontraron modelos compatibles.")
        return

    print(f"Modelos encontrados: {len(modelos)}")
    print("\nIniciando pruebas individuales...\n")

    resultados = []

    for indice, modelo in enumerate(modelos, 1):

        print(
            f"\nProgreso: {indice}/{len(modelos)}"
        )

        resultado = probar_modelo(modelo)

        resultados.append(resultado)

        # Guardar progreso después de cada modelo
        guardar_resultados(resultados)

        if indice < len(modelos):
            time.sleep(PAUSA_ENTRE_MODELOS)

    mostrar_resumen(resultados)

    guardar_resultados(resultados)


if __name__ == "__main__":
    main()
