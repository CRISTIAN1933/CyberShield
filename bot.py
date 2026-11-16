
import os
import re
import html
import json
import logging
import sqlite3
import asyncio

from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from prompts import SYSTEM_PROMPT
import httpx

from dotenv import load_dotenv

from telegram import Update, BotCommand
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)


# ============================================================
# 1. CONFIGURACIÓN GENERAL
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cybershield.db"

DATA_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")

TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-robotics-er-2-preview"
).strip()

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    ""
).strip()

BOT_NAME = os.getenv("BOT_NAME", "CyberShield")

MAX_MESSAGE_LENGTH = int(
    os.getenv("MAX_MESSAGE_LENGTH", "8000")
)

GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/"
    f"v1beta/models/{GEMINI_MODEL}:generateContent"
)

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"

TIMEOUT = httpx.Timeout(25.0, connect=10.0)


# ============================================================
# 2. REGISTRO DE ERRORES
# ============================================================

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO
)

logger = logging.getLogger("CyberShield")


# ============================================================
# 3. BASE DE DATOS SQLITE
# ============================================================

def conectar_db():

    return sqlite3.connect(DB_PATH)


def inicializar_db():

    with conectar_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS historial (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                tipo TEXT NOT NULL,

                riesgo TEXT NOT NULL,

                resumen TEXT,

                fecha TEXT NOT NULL

            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_historial_usuario
            ON historial(user_id)
        """)

        conn.commit()

    logger.info("Base de datos inicializada.")


def guardar_historial(
    user_id: int,
    tipo: str,
    riesgo: str,
    resumen: str
):

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # No almacenamos el mensaje original.
    # Solo guardamos el resultado resumido.

    with conectar_db() as conn:

        conn.execute(
            """
            INSERT INTO historial
            (user_id, tipo, riesgo, resumen, fecha)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                tipo,
                riesgo,
                resumen[:500],
                fecha
            )
        )

        conn.commit()


def obtener_historial(user_id: int):

    with conectar_db() as conn:

        return conn.execute(
            """
            SELECT tipo, riesgo, resumen, fecha
            FROM historial
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (user_id,)
        ).fetchall()


def eliminar_historial(user_id: int):

    with conectar_db() as conn:

        conn.execute(
            "DELETE FROM historial WHERE user_id = ?",
            (user_id,)
        )

        conn.commit()


# ============================================================
# 4. FUNCIONES AUXILIARES
# ============================================================

def obtener_nombre(update: Update):

    usuario = update.effective_user

    if usuario and usuario.first_name:
        return usuario.first_name

    return "Usuario"


def escapar(texto: str):

    return html.escape(str(texto))


def extraer_urls(texto: str):

    patron = r"https?://[^\s<>\"']+"

    encontrados = re.findall(
        patron,
        texto,
        flags=re.IGNORECASE
    )

    resultado = []

    for url in encontrados:

        url = url.rstrip(".,;:!?)\"]}")

        if url not in resultado:
            resultado.append(url)

    return resultado


def validar_url(url: str):

    try:

        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if parsed.username or parsed.password:
            return False

        return True

    except Exception:

        return False


def extraer_nivel_riesgo(texto: str):

    texto = texto.lower()

    if "crítico" in texto or "critico" in texto:
        return "CRÍTICO"

    if "alto" in texto:
        return "ALTO"

    if "medio" in texto:
        return "MEDIO"

    if "bajo" in texto:
        return "BAJO"

    return "NO DETERMINADO"


def nivel_visual(nivel: str):

    niveles = {

        "CRÍTICO": "🔴 CRÍTICO",
        "ALTO": "🔴 ALTO",
        "MEDIO": "🟠 MEDIO",
        "BAJO": "🟢 BAJO",
        "NO DETERMINADO": "⚪ NO DETERMINADO"

    }

    return niveles.get(
        nivel,
        "⚪ NO DETERMINADO"
    )


async def responder(
    update: Update,
    texto: str,
    **kwargs
):

    if update.effective_message:

        await update.effective_message.reply_text(
            texto,
            **kwargs
        )


# ============================================================
# 5. ANÁLISIS PRELIMINAR SIN INTELIGENCIA ARTIFICIAL
# ============================================================

def analizar_indicadores(texto: str):

    texto_lower = texto.lower()

    indicadores = []
    puntuacion = 0

    grupos = {

        "urgencia": {

            "palabras": [
                "urgente",
                "inmediatamente",
                "última oportunidad",
                "ultima oportunidad",
                "último aviso",
                "ultimo aviso",
                "en 10 minutos",
                "en 24 horas",
                "cuenta suspendida",
                "será bloqueada",
                "sera bloqueada",
                "acción inmediata",
                "accion inmediata"
            ],

            "puntos": 2,

            "descripcion":
            "Utiliza urgencia o presión para provocar una reacción rápida."

        },

        "datos": {

            "palabras": [
                "contraseña",
                "contrasena",
                "clave bancaria",
                "datos bancarios",
                "número de tarjeta",
                "numero de tarjeta",
                "código de verificación",
                "codigo de verificacion",
                "código sms",
                "codigo sms",
                "pin de seguridad"
            ],

            "puntos": 3,

            "descripcion":
            "Solicita información personal, financiera o credenciales."

        },

        "premios": {

            "palabras": [
                "ganaste un premio",
                "has ganado",
                "premio gratis",
                "regalo exclusivo",
                "eres el ganador",
                "reclama tu premio",
                "dinero gratis",
                "transferencia gratuita"
            ],

            "puntos": 2,

            "descripcion":
            "Presenta una oferta o recompensa que podría utilizarse como engaño."

        },

        "suplantacion": {

            "palabras": [
                "somos su banco",
                "somos tu banco",
                "soporte técnico",
                "soporte tecnico",
                "administrador de tu cuenta",
                "equipo de seguridad",
                "verificar su identidad",
                "confirmar su identidad"
            ],

            "puntos": 2,

            "descripcion":
            "Podría estar intentando suplantar a una entidad o servicio."

        },

        "pagos": {

            "palabras": [
                "realiza el pago",
                "realizar el pago",
                "envía dinero",
                "envia dinero",
                "transferencia inmediata",
                "paga ahora",
                "depositá",
                "deposita",
                "mercado pago"
            ],

            "puntos": 1,

            "descripcion":
            "Solicita una operación económica que conviene verificar."

        }

    }

    for grupo in grupos.values():

        coincidencias = [
            palabra
            for palabra in grupo["palabras"]
            if palabra in texto_lower
        ]

        if coincidencias:

            indicadores.append(
                grupo["descripcion"]
            )

            puntuacion += grupo["puntos"]

    urls = extraer_urls(texto)

    if urls:

        indicadores.append(
            f"Contiene {len(urls)} enlace(s) que deben verificarse."
        )

        puntuacion += 2

    if re.search(
        r"\b\d{4,8}\b",
        texto
    ):

        indicadores.append(
            "Contiene una secuencia numérica que podría ser un código."
        )

        puntuacion += 1

    if puntuacion >= 7:
        riesgo = "CRÍTICO"

    elif puntuacion >= 5:
        riesgo = "ALTO"

    elif puntuacion >= 2:
        riesgo = "MEDIO"

    else:
        riesgo = "BAJO"

    return {
        "riesgo": riesgo,
        "puntuacion": puntuacion,
        "indicadores": indicadores,
        "urls": urls
    }


# ============================================================
# 6. INTELIGENCIA ARTIFICIAL - GOOGLE GEMINI
# ============================================================

async def analizar_con_gemini(texto: str):

    if not GEMINI_API_KEY:
        return None

    payload = {
        "system_instruction": {
            "parts": [
                {
                    "text": SYSTEM_PROMPT
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": (
                            "Analiza el siguiente contenido no confiable:\n\n"
                            + texto[:MAX_MESSAGE_LENGTH]
                        )
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1800
        }
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                GEMINI_URL,
                params={"key": GEMINI_API_KEY},
                json=payload
            )
            response.raise_for_status()
            data = response.json()

        candidatos = data.get("candidates", [])

        if not candidatos:
            return None

        partes = candidatos[0].get("content", {}).get("parts", [])

        resultado = "\n".join(
            parte.get("text", "")
            for parte in partes
            if parte.get("text")
        ).strip()

        return resultado or None

    except httpx.HTTPStatusError as error:
        logger.error(
            "Error HTTP de Gemini: %s",
            error.response.status_code
        )
        return None

    except Exception:
        logger.exception("Error al comunicarse con Gemini.")
        return None

# ============================================================
# 7. VIRUSTOTAL - VERIFICACIÓN DE ENLACES
# ============================================================

async def verificar_virustotal(url: str):

    if not VIRUSTOTAL_API_KEY:

        return {
            "disponible": False,
            "mensaje":
            "VirusTotal no está configurado."
        }

    if not validar_url(url):

        return {
            "disponible": False,
            "mensaje":
            "El enlace no tiene un formato válido."
        }

    headers = {

        "x-apikey": VIRUSTOTAL_API_KEY

    }

    try:

        async with httpx.AsyncClient(
            timeout=TIMEOUT
        ) as client:

            # Enviar URL para análisis.

            envio = await client.post(

                f"{VIRUSTOTAL_URL}/urls",

                headers=headers,

                data={
                    "url": url
                }

            )

            envio.raise_for_status()

            resultado_envio = envio.json()

            analysis_id = resultado_envio.get(
                "data", {}
            ).get("id")

            if not analysis_id:

                return {
                    "disponible": False,
                    "mensaje":
                    "No se pudo obtener el identificador del análisis."
                }

            # Esperar a que termine el análisis.

            datos = None

            for intento in range(5):

                await asyncio.sleep(2)

                consulta = await client.get(

                    f"{VIRUSTOTAL_URL}/analyses/{analysis_id}",

                    headers=headers

                )

                consulta.raise_for_status()

                datos = consulta.json()

                atributos = datos.get(
                    "data", {}
                ).get("attributes", {})

                estado = atributos.get("status")

                if estado == "completed":
                    break

            if not datos:

                return {
                    "disponible": False,
                    "mensaje":
                    "No se obtuvo respuesta de VirusTotal."
                }

            atributos = datos.get(
                "data", {}
            ).get("attributes", {})

            estadisticas = atributos.get(
                "stats", {}
            )

            if atributos.get("status") != "completed":

                return {

                    "disponible": True,

                    "completado": False,

                    "mensaje":
                    "El análisis fue enviado, pero todavía está procesándose."

                }

            maliciosos = estadisticas.get(
                "malicious", 0
            )

            sospechosos = estadisticas.get(
                "suspicious", 0
            )

            inofensivos = estadisticas.get(
                "harmless", 0
            )

            no_detectados = estadisticas.get(
                "undetected", 0
            )

            if maliciosos >= 3:
                riesgo = "CRÍTICO"

            elif maliciosos > 0:
                riesgo = "ALTO"

            elif sospechosos > 0:
                riesgo = "MEDIO"

            else:
                riesgo = "BAJO"

            return {

                "disponible": True,

                "completado": True,

                "riesgo": riesgo,

                "maliciosos": maliciosos,

                "sospechosos": sospechosos,

                "inofensivos": inofensivos,

                "no_detectados": no_detectados,

                "total": sum(
                    estadisticas.values()
                )

            }

    except httpx.HTTPStatusError as error:

        codigo = error.response.status_code

        logger.error(
            "Error de VirusTotal: HTTP %s",
            codigo
        )

        if codigo == 429:

            mensaje = (
                "Se alcanzó el límite de consultas de VirusTotal. "
                "Intentá nuevamente más tarde."
            )

        elif codigo == 401:

            mensaje = (
                "La API Key de VirusTotal no es válida."
            )

        elif codigo == 403:

            mensaje = (
                "VirusTotal no permite realizar esta operación "
                "con los permisos actuales."
            )

        else:

            mensaje = (
                "No se pudo completar la verificación."
            )

        return {
            "disponible": False,
            "mensaje": mensaje
        }

    except Exception:

        logger.exception(
            "Error al verificar enlace."
        )

        return {

            "disponible": False,

            "mensaje":
            "Ocurrió un error al consultar VirusTotal."

        }


# ============================================================
# 8. CONSTRUCCIÓN DEL INFORME DE ANÁLISIS
# ============================================================

def crear_informe_basico(texto: str):

    datos = analizar_indicadores(texto)

    indicadores = datos["indicadores"]

    respuesta = [

        "🛡️ <b>CYBERSHIELD | INFORME DE SEGURIDAD</b>",

        "",

        f"📊 <b>Nivel de riesgo:</b> "
        f"{nivel_visual(datos['riesgo'])}",

        f"🎯 <b>Puntuación orientativa:</b> "
        f"{datos['puntuacion']} puntos",

        "",

        "🔍 <b>INDICADORES DETECTADOS</b>",

    ]

    if indicadores:

        for indicador in indicadores:

            respuesta.append(
                "• " + escapar(indicador)
            )

    else:

        respuesta.append(
            "• No se detectaron indicadores básicos."
        )

    respuesta.extend([

        "",

        "📝 <b>CONCLUSIÓN</b>",

        "El análisis preliminar se basa en patrones "
        "de lenguaje y características del contenido.",

        "",

        "🛡️ <b>RECOMENDACIÓN</b>",

        "No compartas contraseñas, códigos de verificación "
        "ni datos bancarios con remitentes desconocidos.",

    ])

    return "\n".join(respuesta), datos


# ============================================================
# 9. COMANDO START
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    context.user_data["modo"] = None

    nombre = escapar(
        obtener_nombre(update)
    )

    mensaje = f"""
🛡️ <b>¡Bienvenido a {BOT_NAME}, {nombre}!</b>

Tu asistente inteligente de ciberseguridad.

Estoy preparado para ayudarte a identificar
amenazas y proteger tu información digital.

<b>¿QUÉ PUEDO HACER?</b>

🔍 Analizar mensajes sospechosos.
🌐 Verificar enlaces con VirusTotal.
🤖 Analizar posibles estafas con inteligencia artificial.
🚨 Detectar señales de phishing.
🔐 Enseñarte a proteger tus cuentas.
📊 Consultar tus análisis anteriores.

<b>COMANDOS PRINCIPALES</b>

/analizar - Analizar un mensaje.
/verificar - Verificar un enlace.
/seguridad - Consejos de protección.
/historial - Consultar tus análisis.
/privacidad - Información sobre tus datos.
/cancelar - Cancelar una operación.
/help - Ver todos los comandos.

🛡️ <i>Tu seguridad digital comienza aquí.</i>
"""

    await responder(
        update,
        mensaje,
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 10. AYUDA
# ============================================================

async def help_command(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    mensaje = """
🛡️ <b>CYBERSHIELD | CENTRO DE AYUDA</b>

<b>ANÁLISIS DE SEGURIDAD</b>

/analizar
Activa el análisis de mensajes sospechosos.

/verificar
Comprueba un enlace mediante VirusTotal.

/seguridad
Obtiene consejos de ciberseguridad.

<b>GESTIÓN</b>

/start
Inicia el asistente.

/help
Muestra esta ayuda.

/historial
Consulta tus últimos 10 análisis.

/borrarhistorial
Elimina tu historial.

/privacidad
Explica cómo se gestionan tus datos.

/cancelar
Cancela la operación actual.

<b>¿CÓMO UTILIZARLO?</b>

1. Escribí /analizar.
2. Enviá el mensaje sospechoso.
3. Esperá el informe de CyberShield.

Para comprobar un enlace:

1. Escribí /verificar.
2. Enviá el enlace.
3. Recibirás el resultado de VirusTotal.

⚠️ Los resultados son orientativos y no garantizan
que un contenido sea seguro o malicioso.
"""

    await responder(
        update,
        mensaje,
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 11. ACTIVAR MODO ANÁLISIS
# ============================================================

async def analizar(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    context.user_data["modo"] = "analizar"

    await responder(
        update,
        """
🔍 <b>MODO DE ANÁLISIS ACTIVADO</b>

Enviame el mensaje que querés investigar.

Examinaré:

• Phishing.
• Suplantación de identidad.
• Ingeniería social.
• Solicitudes de información confidencial.
• Intentos de estafa.
• Enlaces sospechosos.
• Manipulación y urgencia artificial.

🤖 Utilizaré inteligencia artificial cuando esté configurada.

⚠️ No envíes contraseñas ni códigos reales.
        
Escribí /cancelar para salir.
""",
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 12. ACTIVAR MODO VERIFICACIÓN
# ============================================================

async def verificar(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if context.args:

        url = " ".join(context.args)

        await procesar_verificacion(
            update,
            url
        )

        return

    context.user_data["modo"] = "verificar"

    await responder(
        update,
        """
🌐 <b>VERIFICACIÓN DE ENLACES</b>

Enviame el enlace que querés comprobar.

CyberShield intentará analizarlo mediante VirusTotal.

📊 Recibirás:

• Detecciones maliciosas.
• Detecciones sospechosas.
• Detecciones inofensivas.
• Resultado general del análisis.

⚠️ Una URL puede ser peligrosa aunque VirusTotal
no detecte amenazas.

Escribí /cancelar para salir.
""",
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 13. PROCESAR VERIFICACIÓN
# ============================================================

async def procesar_verificacion(
    update: Update,
    url: str
):

    url = url.strip()

    if not validar_url(url):

        await responder(
            update,
            "❌ El enlace no es válido.\n\n"
            "Enviá una dirección que comience con "
            "http:// o https://."
        )

        return

    await responder(
        update,
        "🔎 Analizando el enlace...\n\n"
        "Consultando VirusTotal. Esto puede tardar unos segundos."
    )

    resultado = await verificar_virustotal(url)

    if not resultado["disponible"]:

        await responder(
            update,
            "⚠️ <b>VERIFICACIÓN NO DISPONIBLE</b>\n\n"
            + escapar(resultado["mensaje"]),
            parse_mode=ParseMode.HTML
        )

        return

    if not resultado.get("completado"):

        await responder(
            update,
            "⏳ <b>ANÁLISIS PENDIENTE</b>\n\n"
            "VirusTotal recibió el enlace, pero el análisis "
            "todavía no terminó.\n\n"
            "Podés volver a intentarlo más tarde.",
            parse_mode=ParseMode.HTML
        )

        return

    riesgo = resultado["riesgo"]

    mensaje = f"""
🌐 <b>CYBERSHIELD | INFORME DE URL</b>

📊 <b>Nivel de riesgo:</b> {nivel_visual(riesgo)}

🔍 <b>RESULTADOS DE VIRUSTOTAL</b>

🔴 Detecciones maliciosas:
{resultado['maliciosos']}

🟠 Detecciones sospechosas:
{resultado['sospechosos']}

🟢 Detecciones inofensivas:
{resultado['inofensivos']}

⚪ Sin detección:
{resultado['no_detectados']}

📊 Total de resultados:
{resultado['total']}

🛡️ <b>RECOMENDACIÓN</b>
"""

    if riesgo in ("CRÍTICO", "ALTO"):

        mensaje += (
            "\nNo abras el enlace ni introduzcas información "
            "personal. La detección debe tomarse muy en serio."
        )

    elif riesgo == "MEDIO":

        mensaje += (
            "\nActuá con precaución. Verificá el dominio "
            "y la procedencia del enlace."
        )

    else:

        mensaje += (
            "\nNo se encontraron detecciones maliciosas "
            "en este análisis. Esto no garantiza que el "
            "enlace sea seguro."
        )

    mensaje += """

⚠️ Los resultados dependen de los motores de detección
consultados y pueden cambiar con el tiempo.
"""

    await responder(
        update,
        mensaje,
        parse_mode=ParseMode.HTML
    )

    guardar_historial(
        update.effective_user.id,
        "Verificación URL",
        riesgo,
        f"Resultado VirusTotal: {riesgo}"
    )


# ============================================================
# 14. RECIBIR Y PROCESAR MENSAJES
# ============================================================

async def recibir_mensaje(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not update.message or not update.message.text:
        return

    mensaje = update.message.text.strip()

    modo = context.user_data.get("modo")

    if not mensaje:

        await responder(
            update,
            "⚠️ El mensaje está vacío."
        )

        return

    if len(mensaje) > MAX_MESSAGE_LENGTH:

        await responder(
            update,
            f"⚠️ El texto es demasiado largo.\n\n"
            f"Máximo permitido: {MAX_MESSAGE_LENGTH} caracteres."
        )

        return

    # --------------------------------------------------------
    # MODO ANALIZAR
    # --------------------------------------------------------

    if modo == "analizar":

        context.user_data["modo"] = None

        await responder(
            update,
            "🔍 Analizando el contenido...\n\n"
            "Esto puede tardar unos segundos."
        )

        resultado_ia = await analizar_con_gemini(
            mensaje
        )

        datos_basicos = analizar_indicadores(
            mensaje
        )

        if resultado_ia:

            nivel = extraer_nivel_riesgo(
                resultado_ia
            )

            if nivel == "NO DETERMINADO":

                nivel = datos_basicos["riesgo"]

            informe = (
                "🤖 <b>ANÁLISIS INTELIGENTE</b>\n\n"
                + escapar(resultado_ia)
            )

            informe += (
                "\n\n⚠️ <i>El análisis de IA es orientativo. "
                "No confirma por sí solo que un mensaje sea "
                "fraudulento.</i>"
            )

        else:

            informe, datos_basicos = crear_informe_basico(
                mensaje
            )

            nivel = datos_basicos["riesgo"]

            informe += (
                "\n\n🤖 <i>La IA no está disponible. "
                "Se utilizó el análisis preliminar local.</i>"
            )

        guardar_historial(
            update.effective_user.id,
            "Análisis de mensaje",
            nivel,
            "Análisis completado."
        )

        await responder(
            update,
            informe,
            parse_mode=ParseMode.HTML
        )

        return

    # --------------------------------------------------------
    # MODO VERIFICAR
    # --------------------------------------------------------

    if modo == "verificar":

        urls = extraer_urls(mensaje)

        if not urls:

            if validar_url(mensaje):
                urls = [mensaje]

        if not urls:

            await responder(
                update,
                "❌ No encontré un enlace válido.\n\n"
                "Enviá una dirección como:\n"
                "https://ejemplo.com"
            )

            return

        context.user_data["modo"] = None

        if len(urls) > 3:

            await responder(
                update,
                "⚠️ Enviá como máximo 3 enlaces por operación."
            )

            return

        for url in urls:

            await procesar_verificacion(
                update,
                url
            )

        return

    # --------------------------------------------------------
    # SIN MODO ACTIVO
    # --------------------------------------------------------

    urls = extraer_urls(mensaje)

    if urls:

        await responder(
            update,
            "🌐 Detecté un enlace en tu mensaje.\n\n"
            "Utilizá /verificar para comprobarlo con VirusTotal "
            "o /analizar para examinar el mensaje completo."
        )

    else:

        await responder(
            update,
            "👋 ¡Hola! Estoy disponible para ayudarte.\n\n"
            "Utilizá:\n\n"
            "🔍 /analizar - Investigar un mensaje.\n"
            "🌐 /verificar - Comprobar un enlace.\n"
            "🔐 /seguridad - Consejos de protección.\n"
            "📚 /help - Ver todos los comandos."
        )


# ============================================================
# 15. CONSEJOS DE SEGURIDAD
# ============================================================

CONSEJOS = [

    """
🔐 <b>PROTECCIÓN DE CONTRASEÑAS</b>

• Utilizá contraseñas únicas.
• Evitá utilizar fechas de nacimiento.
• No compartas tus contraseñas.
• Utilizá un gestor de contraseñas.
• Activá la autenticación multifactor.
""",

    """
🌐 <b>NAVEGACIÓN SEGURA</b>

• Verificá las direcciones de las páginas.
• No abras enlaces desconocidos.
• Comprobá el dominio antes de iniciar sesión.
• Desconfiá de páginas que imitan servicios conocidos.
• Utilizá conexiones seguras.
""",

    """
🚨 <b>PREVENCIÓN DE ESTAFAS</b>

• Desconfiá de premios inesperados.
• No envíes dinero por presión.
• Verificá las solicitudes de transferencias.
• No compartas códigos recibidos por SMS.
• Contactá a la entidad por canales oficiales.
""",

    """
📱 <b>PROTECCIÓN DEL CELULAR</b>

• Mantené actualizado el sistema.
• Instalá aplicaciones de fuentes confiables.
• Revisá los permisos de las aplicaciones.
• Activá el bloqueo de pantalla.
• Evitá conectar dispositivos USB desconocidos.
""",

    """
📧 <b>SEGURIDAD DEL CORREO</b>

• Revisá quién envía el mensaje.
• Desconfiá de archivos inesperados.
• No habilites macros desconocidas.
• No respondas solicitudes de contraseñas.
• Activá la verificación en dos pasos.
"""

]


async def seguridad(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    import random

    consejo = random.choice(CONSEJOS)

    await responder(
        update,
        "🛡️ <b>CYBERSHIELD | CONSEJO DE SEGURIDAD</b>\n\n"
        + consejo,
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 16. HISTORIAL
# ============================================================

async def historial(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    user_id = update.effective_user.id

    registros = obtener_historial(
        user_id
    )

    if not registros:

        await responder(
            update,
            "📚 Todavía no tenés análisis registrados."
        )

        return

    mensaje = [
        "📚 <b>CYBERSHIELD | TU HISTORIAL</b>",
        ""
    ]

    for indice, registro in enumerate(
        registros,
        start=1
    ):

        tipo, riesgo, resumen, fecha = registro

        mensaje.extend([

            f"<b>{indice}. {escapar(tipo)}</b>",

            f"📊 Riesgo: {nivel_visual(riesgo)}",

            f"📝 {escapar(resumen)}",

            f"🕒 {escapar(fecha)}",

            ""

        ])

    mensaje.append(
        "Se muestran tus últimos 10 registros."
    )

    await responder(
        update,
        "\n".join(mensaje),
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 17. ELIMINAR HISTORIAL
# ============================================================

async def borrar_historial(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    eliminar_historial(
        update.effective_user.id
    )

    await responder(
        update,
        "🗑️ <b>HISTORIAL ELIMINADO</b>\n\n"
        "Tus registros de análisis fueron eliminados correctamente.",
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 18. PRIVACIDAD
# ============================================================

async def privacidad(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    mensaje = """
🔐 <b>CYBERSHIELD | PRIVACIDAD</b>

Tu privacidad es importante.

<b>¿QUÉ INFORMACIÓN SE GUARDA?</b>

• Identificador de Telegram.
• Tipo de análisis realizado.
• Nivel de riesgo obtenido.
• Resumen del resultado.
• Fecha del análisis.

<b>¿QUÉ NO SE GUARDA?</b>

• Contraseñas.
• Códigos de verificación.
• El contenido original de tus mensajes.

<b>¿DÓNDE SE GUARDA?</b>

Los registros se almacenan localmente en una base
de datos SQLite del servidor donde funciona el bot.

<b>¿CÓMO ELIMINAR TUS REGISTROS?</b>

/borrarhistorial

⚠️ Cuando utilizás servicios externos como Gemini
o VirusTotal, el contenido o enlace enviado puede
ser procesado por dichos proveedores según sus
propias políticas de privacidad.

No envíes información confidencial.
"""

    await responder(
        update,
        mensaje,
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 19. CANCELAR OPERACIONES
# ============================================================

async def cancelar(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    context.user_data["modo"] = None

    await responder(
        update,
        "❌ <b>OPERACIÓN CANCELADA</b>\n\n"
        "Ya no estoy esperando ningún mensaje.\n\n"
        "Podés iniciar otra operación con /analizar "
        "o /verificar.",
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 20. INFORMACIÓN DEL BOT
# ============================================================

async def acerca(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    mensaje = """
🛡️ <b>ACERCA DE CYBERSHIELD</b>

CyberShield es un asistente de ciberseguridad
diseñado para ayudar a identificar posibles
amenazas digitales.

<b>TECNOLOGÍAS</b>

🐍 Python.
📱 Telegram Bot API.
🤖 Google Gemini.
🌐 VirusTotal.
🗄️ SQLite.

<b>FUNCIONES</b>

• Análisis de phishing.
• Detección de ingeniería social.
• Verificación de enlaces.
• Prevención de estafas.
• Educación en ciberseguridad.

CyberShield es una herramienta de asistencia
y prevención, no un sistema de certificación
de seguridad informática.
"""

    await responder(
        update,
        mensaje,
        parse_mode=ParseMode.HTML
    )


# ============================================================
# 21. REGISTRAR COMANDOS EN TELEGRAM
# ============================================================

async def configurar_comandos(
    app: Application
):

    comandos = [

        BotCommand("start", "Iniciar CyberShield"),

        BotCommand("help", "Mostrar ayuda"),

        BotCommand("analizar", "Analizar un mensaje"),

        BotCommand("verificar", "Verificar un enlace"),

        BotCommand("seguridad", "Consejos de seguridad"),

        BotCommand("historial", "Consultar historial"),

        BotCommand("borrarhistorial", "Eliminar historial"),

        BotCommand("privacidad", "Consultar privacidad"),

        BotCommand("cancelar", "Cancelar operación"),

        BotCommand("acerca", "Información del bot")

    ]

    await app.bot.set_my_commands(
        comandos
    )

    logger.info(
        "Comandos de Telegram configurados."
    )


# ============================================================
# 22. MANEJO GLOBAL DE ERRORES
# ============================================================

async def manejar_error(
    update: object,
    context: ContextTypes.DEFAULT_TYPE
):

    logger.error(
        "Error no controlado en CyberShield.",
        exc_info=context.error
    )

    if isinstance(update, Update):

        if update.effective_message:

            try:

                await update.effective_message.reply_text(
                    "⚠️ Ocurrió un error inesperado.\n\n"
                    "Intentá nuevamente dentro de unos segundos."
                )

            except Exception:

                logger.exception(
                    "No se pudo informar el error al usuario."
                )


# ============================================================
# 23. INICIALIZACIÓN
# ============================================================

async def post_init(
    app: Application
):

    inicializar_db()

    await configurar_comandos(
        app
    )

    logger.info(
        "CyberShield inicializado correctamente."
    )


# ============================================================
# 24. FUNCIÓN PRINCIPAL
# ============================================================

def main():

    if not TOKEN:

        raise RuntimeError(
            "No se encontró TELEGRAM_TOKEN en el archivo .env"
        )

    app = (

        Application.builder()

        .token(TOKEN)

        .post_init(post_init)

        .build()

    )

    # --------------------------------------------------------
    # COMANDOS
    # --------------------------------------------------------

    app.add_handler(
        CommandHandler("start", start)
    )

    app.add_handler(
        CommandHandler("help", help_command)
    )

    app.add_handler(
        CommandHandler("analizar", analizar)
    )

    app.add_handler(
        CommandHandler("verificar", verificar)
    )

    app.add_handler(
        CommandHandler("seguridad", seguridad)
    )

    app.add_handler(
        CommandHandler("historial", historial)
    )

    app.add_handler(
        CommandHandler("borrarhistorial", borrar_historial)
    )

    app.add_handler(
        CommandHandler("privacidad", privacidad)
    )

    app.add_handler(
        CommandHandler("cancelar", cancelar)
    )

    app.add_handler(
        CommandHandler("acerca", acerca)
    )

    # --------------------------------------------------------
    # MENSAJES DE TEXTO
    # --------------------------------------------------------

    app.add_handler(

        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            recibir_mensaje
        )

    )

    # --------------------------------------------------------
    # MENSAJES QUE NO SON TEXTO
    # --------------------------------------------------------

    async def mensaje_no_soportado(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE
    ):

        await responder(
            update,
            "⚠️ Por ahora puedo analizar mensajes de texto "
            "y verificar enlaces.\n\n"
            "Utilizá /help para ver las funciones disponibles."
        )

    app.add_handler(

        MessageHandler(
            ~filters.TEXT & ~filters.COMMAND,
            mensaje_no_soportado
        )

    )

    # --------------------------------------------------------
    # ERRORES
    # --------------------------------------------------------

    app.add_error_handler(
        manejar_error
    )

    # --------------------------------------------------------
    # EJECUCIÓN
    # --------------------------------------------------------

    logger.info(
        "======================================"
    )

    logger.info(
        "🛡️ CYBERSHIELD ESTÁ INICIANDO"
    )

    logger.info(
        "Gemini: %s",
        "ACTIVADO" if GEMINI_API_KEY else "NO CONFIGURADO"
    )

    logger.info(
        "VirusTotal: %s",
        "ACTIVADO" if VIRUSTOTAL_API_KEY else "NO CONFIGURADO"
    )

    logger.info(
        "======================================"
    )

    app.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True
    )


# ============================================================
# 25. EJECUCIÓN DEL PROGRAMA
# ============================================================

if __name__ == "__main__":

    main()
