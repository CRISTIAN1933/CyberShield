import os
import re
import html
import base64
import hashlib
import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

logger = logging.getLogger("CyberShield.VT")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = httpx.Timeout(60.0, connect=15.0)

MAX_VT_FILE_SIZE = 650 * 1024 * 1024  # 650 MB
STANDARD_VT_LIMIT = 32 * 1024 * 1024  # 32 MB


def escapar(texto) -> str:
    return html.escape(str(texto))


def formatear_fecha_unix(timestamp: int | None) -> str:
    if not timestamp:
        return "Desconocida"
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Desconocida"


def detectar_tipo_indicador(entrada: str) -> tuple[str, str]:
    """
    Detecta automáticamente si la entrada es:
    - 'hash' (MD5, SHA1, SHA256)
    - 'ip' (IPv4)
    - 'url' (http:// o https://)
    - 'domain' (ejemplo.com)
    - 'desconocido'
    """
    valor = entrada.strip()

    # 1. Hash (MD5: 32, SHA1: 40, SHA256: 64)
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", valor):
        return "hash", valor.lower()

    # 2. Dirección IPv4
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", valor):
        partes = [int(p) for p in valor.split(".")]
        if all(0 <= p <= 255 for p in partes):
            return "ip", valor

    # 3. URL completa
    if valor.lower().startswith(("http://", "https://")):
        parsed = urlparse(valor)
        if parsed.hostname:
            return "url", valor

    # 4. Dominio
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", valor):
        return "domain", valor.lower()

    return "desconocido", valor


def _extraer_detalles_motores(last_analysis_results: dict) -> dict:
    """
    Clasifica cada motor de seguridad exactamente como la web de VirusTotal:
    - malicious / suspicious
    - harmless / undetected (Clean / Undetected)
    - type-unsupported / timeout / failure (Unable to process / Unrated)
    """
    detectados = []
    limpios = []
    no_procesados = []

    for motor, info in sorted(last_analysis_results.items(), key=lambda x: x[0].lower()):
        categoria = info.get("category", "")
        resultado = info.get("result") or categoria

        if categoria in ("malicious", "suspicious"):
            icono = "🔴" if categoria == "malicious" else "🟠"
            detectados.append(f"{icono} <b>{escapar(motor)}:</b> {escapar(resultado)}")
        elif categoria in ("harmless", "undetected"):
            etiqueta = "Clean" if categoria == "harmless" else "Undetected"
            limpios.append(f"{escapar(motor)} ({etiqueta})")
        else:
            no_procesados.append(escapar(motor))

    return {
        "detectados": detectados,
        "limpios": limpios,
        "no_procesados": no_procesados,
    }


def _calcular_riesgo(stats: dict) -> str:
    maliciosos = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    if maliciosos >= 3:
        return "CRÍTICO"
    if maliciosos > 0:
        return "ALTO"
    if sospechosos > 0:
        return "MEDIO"
    return "BAJO"


def _construir_reporte_vt(tipo: str, identificador: str, data_obj: dict) -> dict:
    """
    Construye un reporte enriquecido estilo VirusTotal (Detection, Details, Community).
    """
    atributos = data_obj.get("attributes", {})
    stats = atributos.get("last_analysis_stats", {})
    results = atributos.get("last_analysis_results", {})
    motores = _extraer_detalles_motores(results)

    maliciosos = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    inofensivos = stats.get("harmless", 0)
    no_detectados = stats.get("undetected", 0)
    total_motores = maliciosos + sospechosos + inofensivos + no_detectados

    reputacion = atributos.get("reputation", 0)
    votos = atributos.get("total_votes", {})
    votos_mal = votos.get("malicious", 0)
    votos_harmless = votos.get("harmless", 0)
    fecha_analisis = formatear_fecha_unix(atributos.get("last_analysis_date"))
    riesgo = _calcular_riesgo(stats)

    # Enlace directo a la GUI de VirusTotal
    if tipo == "hash":
        vt_gui_url = f"https://www.virustotal.com/gui/file/{identificador}/detection"
    elif tipo == "ip":
        vt_gui_url = f"https://www.virustotal.com/gui/ip-address/{identificador}/detection"
    elif tipo == "domain":
        vt_gui_url = f"https://www.virustotal.com/gui/domain/{identificador}/detection"
    else:
        url_id = base64.urlsafe_b64encode(identificador.encode()).decode().strip("=")
        vt_gui_url = f"https://www.virustotal.com/gui/url/{url_id}/detection"

    # Detalles específicos según el tipo (Details & Contextual Indicators)
    detalles_extra = []
    if tipo == "hash":
        nombre = atributos.get("meaningful_name") or (atributos.get("names") or ["Archivo"])[0]
        tamano = atributos.get("size", 0)
        tipo_archivo = atributos.get("type_description", "Desconocido")
        sha256 = atributos.get("sha256", identificador)
        detalles_extra.append(f"📄 <b>Nombre:</b> {escapar(nombre)}")
        detalles_extra.append(f"📦 <b>Tamaño:</b> {tamano:,} bytes")
        detalles_extra.append(f"🧬 <b>Tipo:</b> {escapar(tipo_archivo)}")
        detalles_extra.append(f"🔑 <b>SHA-256:</b> <code>{escapar(sha256)}</code>")

    elif tipo == "domain":
        creacion = formatear_fecha_unix(atributos.get("creation_date"))
        categorias = atributos.get("categories", {})
        ranks = atributos.get("popularity_ranks", {})
        detalles_extra.append(f"📅 <b>Creación:</b> {creacion}")
        if categorias:
            cats_str = ", ".join(f"{v} ({k})" for k, v in list(categorias.items())[:3])
            detalles_extra.append(f"🏷️ <b>Categorías:</b> {escapar(cats_str)}")
        if ranks:
            ranks_str = ", ".join(f"{k}: #{v.get('rank')}" for k, v in ranks.items())
            detalles_extra.append(f"📈 <b>Popularidad:</b> {escapar(ranks_str)}")

    elif tipo == "ip":
        asn = atributos.get("asn", "N/A")
        as_owner = atributos.get("as_owner", "Desconocido")
        pais = atributos.get("country", "N/A")
        red = atributos.get("network", "N/A")
        detalles_extra.append(f"🏢 <b>Propietario AS:</b> {escapar(as_owner)} (ASN {asn})")
        detalles_extra.append(f"🌍 <b>País / Red:</b> {escapar(pais)} | {escapar(red)}")

    elif tipo == "url":
        final_url = atributos.get("last_final_url", identificador)
        titulo_web = atributos.get("title", "")
        http_code = atributos.get("last_http_response_code", "")
        if titulo_web:
            detalles_extra.append(f"📰 <b>Título Web:</b> {escapar(titulo_web)}")
        if http_code:
            detalles_extra.append(f"📡 <b>Estado HTTP:</b> {http_code}")
        if final_url != identificador:
            detalles_extra.append(f"↪️ <b>URL Final:</b> {escapar(final_url)}")

    # Construcción del mensaje HTML estilo VirusTotal
    lineas = [
        f"🛡️ <b>VIRUSTOTAL | ANÁLISIS DE {tipo.upper()}</b>",
        "",
        f"🎯 <b>Score de Detección:</b> <b>{maliciosos + sospechosos} / {total_motores}</b> motores",
        f"⭐ <b>Community Score (Reputación):</b> {reputacion} (👍 {votos_harmless} | 👎 {votos_mal})",
        f"🕒 <b>Último análisis:</b> {fecha_analisis}",
        "",
        "📋 <b>DETAILS & CONTEXTUAL INDICATORS</b>",
        *detalles_extra,
        "",
        "🔍 <b>SECURITY VENDORS' ANALYSIS</b>",
    ]

    if motores["detectados"]:
        lineas.append("<b>⚠️ Motores con detección:</b>")
        lineas.extend(motores["detectados"][:25])
        if len(motores["detectados"]) > 25:
            lineas.append(f"<i>... y {len(motores['detectados']) - 25} detecciones más.</i>")
    else:
        lineas.append("✅ <i>Ningún proveedor de seguridad marcó este elemento como malicioso.</i>")

    lineas.append(f"\n🟢 <b>Clean / Undetected:</b> {len(motores['limpios'])} motores")
    if motores["limpios"]:
        muestra_limpios = ", ".join(motores["limpios"][:15])
        lineas.append(f"<i>({muestra_limpios}...)</i>")

    if motores["no_procesados"]:
        lineas.append(f"⚪ <b>Unable to process / Unrated:</b> {len(motores['no_procesados'])} motores")

    lineas.append(f"\n🔗 <a href='{vt_gui_url}'>Ver informe completo en VirusTotal</a>")

    return {
        "disponible": True,
        "completado": True,
        "riesgo": riesgo,
        "maliciosos": maliciosos,
        "sospechosos": sospechosos,
        "total": total_motores,
        "reputacion": reputacion,
        "vt_url": vt_gui_url,
        "mensaje_html": "\n".join(lineas),
        "resumen_ia": {
            "tipo": tipo,
            "identificador": identificador,
            "maliciosos": maliciosos,
            "sospechosos": sospechosos,
            "total_motores": total_motores,
            "reputacion_comunidad": reputacion,
            "detecciones_especificas": motores["detectados"][:15],
            "enlace_vt": vt_gui_url,
        }
    }


async def _esperar_analisis(client: httpx.AsyncClient, headers: dict, analysis_id: str) -> bool:
    """Espera a que VirusTotal termine de procesar un envío nuevo."""
    for _ in range(12):
        await asyncio.sleep(3)
        resp = await client.get(f"{VIRUSTOTAL_URL}/analyses/{analysis_id}", headers=headers)
        if resp.status_code == 200:
            status = resp.json().get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return True
    return False


async def consultar_virustotal(entrada: str) -> dict:
    """
    Analiza automáticamente cualquier indicador: Hash, IP, Dominio o URL.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"disponible": False, "mensaje": "La API Key de VirusTotal no está configurada."}

    tipo, valor = detectar_tipo_indicador(entrada)
    if tipo == "desconocido":
        return {"disponible": False, "mensaje": "No se reconoció una URL, dominio, IP o hash válido."}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            if tipo == "hash":
                resp = await client.get(f"{VIRUSTOTAL_URL}/files/{valor}", headers=headers)
                if resp.status_code == 404:
                    return {"disponible": False, "mensaje": "Este hash no existe aún en la base de datos de VirusTotal. Subí el archivo para analizarlo."}
                resp.raise_for_status()
                return _construir_reporte_vt("hash", valor, resp.json()["data"])

            elif tipo == "ip":
                resp = await client.get(f"{VIRUSTOTAL_URL}/ip_addresses/{valor}", headers=headers)
                resp.raise_for_status()
                return _construir_reporte_vt("ip", valor, resp.json()["data"])

            elif tipo == "domain":
                resp = await client.get(f"{VIRUSTOTAL_URL}/domains/{valor}", headers=headers)
                resp.raise_for_status()
                return _construir_reporte_vt("domain", valor, resp.json()["data"])

            elif tipo == "url":
                # Primero enviamos a escanear para tener datos frescos
                envio = await client.post(f"{VIRUSTOTAL_URL}/urls", headers=headers, data={"url": valor})
                envio.raise_for_status()
                analysis_id = envio.json().get("data", {}).get("id")
                if analysis_id:
                    await _esperar_analisis(client, headers, analysis_id)

                # Luego consultamos el objeto URL completo (incluye votos, redirecciones, motores)
                url_id = base64.urlsafe_b64encode(valor.encode()).decode().strip("=")
                resp = await client.get(f"{VIRUSTOTAL_URL}/urls/{url_id}", headers=headers)
                resp.raise_for_status()
                return _construir_reporte_vt("url", valor, resp.json()["data"])

    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        if code == 429:
            return {"disponible": False, "mensaje": "Límite de consultas de VirusTotal alcanzado (4 req/min en plan gratuito)."}
        if code == 404:
            return {"disponible": False, "mensaje": "El recurso no fue encontrado en VirusTotal."}
        return {"disponible": False, "mensaje": f"Error HTTP {code} al consultar VirusTotal."}
    except Exception as e:
        logger.exception("Error consultando VirusTotal")
        return {"disponible": False, "mensaje": f"Error interno al consultar VirusTotal: {e}"}


async def analizar_archivo_virustotal(ruta_archivo: str, nombre_original: str) -> dict:
    """
    Sube y analiza un archivo en VirusTotal (soporta hasta 650 MB).
    Primero verifica si su SHA-256 ya fue analizado para ahorrar cuota y tiempo.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"disponible": False, "mensaje": "La API Key de VirusTotal no está configurada."}

    tamano = os.path.getsize(ruta_archivo)
    if tamano > MAX_VT_FILE_SIZE:
        return {"disponible": False, "mensaje": "El archivo supera el límite máximo de 650 MB de VirusTotal."}

    # Calcular SHA-256 local
    sha256_hash = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            sha256_hash.update(bloque)
    sha256 = sha256_hash.hexdigest()

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0)) as client:
            # 1. Consultar si el hash ya existe en VirusTotal
            check = await client.get(f"{VIRUSTOTAL_URL}/files/{sha256}", headers=headers)
            if check.status_code == 200:
                return _construir_reporte_vt("hash", sha256, check.json()["data"])

            # 2. Si no existe, subirlo (<= 32MB directo, > 32MB hasta 650MB via upload_url)
            upload_endpoint = f"{VIRUSTOTAL_URL}/files"
            if tamano > STANDARD_VT_LIMIT:
                url_resp = await client.get(f"{VIRUSTOTAL_URL}/files/upload_url", headers=headers)
                url_resp.raise_for_status()
                upload_endpoint = url_resp.json()["data"]

            with open(ruta_archivo, "rb") as f:
                files = {"file": (nombre_original, f)}
                subida = await client.post(upload_endpoint, headers=headers, files=files)
                subida.raise_for_status()

            analysis_id = subida.json().get("data", {}).get("id")
            if not analysis_id:
                return {"disponible": False, "mensaje": "No se pudo obtener el ID de análisis del archivo."}

            completado = await _esperar_analisis(client, headers, analysis_id)
            if not completado:
                return {
                    "disponible": True,
                    "completado": False,
                    "mensaje": (
                        f"⏳ El archivo <b>{escapar(nombre_original)}</b> se subió correctamente, "
                        f"pero VirusTotal sigue analizándolo.\n\n"
                        f"Podés consultar su hash en unos minutos:\n<code>{sha256}</code>"
                    )
                }

            # 3. Obtener el reporte completo del archivo recién analizado
            reporte = await client.get(f"{VIRUSTOTAL_URL}/files/{sha256}", headers=headers)
            reporte.raise_for_status()
            return _construir_reporte_vt("hash", sha256, reporte.json()["data"])

    except httpx.HTTPStatusError as e:
        return {"disponible": False, "mensaje": f"Error HTTP {e.response.status_code} al subir el archivo a VirusTotal."}
    except Exception as e:
        logger.exception("Error subiendo archivo a VirusTotal")
        return {"disponible": False, "mensaje": f"Ocurrió un error al procesar el archivo: {e}"}