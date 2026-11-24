import asyncio
import base64
import json
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import bot


class RespuestaGeminiFalsa:
    def raise_for_status(self):
        pass

    def json(self):
        return {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "riesgo": "MEDIO",
                            "puntuacion": 45,
                            "resumen": "Contenido de prueba analizado.",
                            "indicadores": [],
                            "recomendaciones": ["Verificar por un canal oficial."],
                            "contiene_url": False,
                            "urls": [],
                            "certeza": "MEDIA"
                        })
                    }]
                }
            }]
        }


class ClienteGeminiFalso:
    payloads = []
    headers = []

    def __init__(self, timeout):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass

    async def post(self, url, headers, json):
        self.payloads.append(json)
        self.headers.append(headers)
        return RespuestaGeminiFalsa()


class AnalisisMultimodalTests(unittest.TestCase):
    def test_recibe_fotos_y_notas_de_voz_en_modo_analizar(self):
        contenido = b"contenido multimedia de prueba"

        for mime_type in ("image/jpeg", "audio/ogg"):
            with self.subTest(mime_type=mime_type):
                archivo = SimpleNamespace(
                    file_id="archivo-prueba",
                    file_size=len(contenido)
                )
                mensaje = SimpleNamespace(
                    photo=[archivo] if mime_type == "image/jpeg" else [],
                    voice=archivo if mime_type == "audio/ogg" else None,
                    caption="texto descriptivo"
                )
                update = SimpleNamespace(effective_message=mensaje)
                descarga = AsyncMock(return_value=bytearray(contenido))
                bot_telegram = SimpleNamespace(
                    get_file=AsyncMock(return_value=SimpleNamespace(
                        download_as_bytearray=descarga
                    ))
                )
                context = SimpleNamespace(
                    user_data={"modo": "analizar"},
                    bot=bot_telegram
                )
                procesar = AsyncMock()

                with patch.object(bot, "procesar_analisis", procesar):
                    asyncio.run(bot.recibir_multimedia(update, context))

                procesar.assert_awaited_once_with(
                    update,
                    "texto descriptivo",
                    {"mime_type": mime_type, "data": contenido}
                )
                self.assertIsNone(context.user_data["modo"])

    def test_incluye_imagen_y_audio_en_la_solicitud_a_gemini(self):
        contenido = b"contenido multimedia de prueba"
        ClienteGeminiFalso.payloads = []
        ClienteGeminiFalso.headers = []

        with patch.object(bot, "GEMINI_API_KEY", "clave-de-prueba"), patch.object(
            bot.httpx, "AsyncClient", ClienteGeminiFalso
        ):
            for mime_type in ("image/jpeg", "audio/ogg"):
                with self.subTest(mime_type=mime_type):
                    resultado = asyncio.run(bot.analizar_con_gemini(
                        "Revisá este contenido",
                        {"mime_type": mime_type, "data": contenido}
                    ))

                    self.assertEqual(resultado.riesgo, "MEDIO")
                    self.assertEqual(
                        ClienteGeminiFalso.headers[-1],
                        {"x-goog-api-key": "clave-de-prueba"}
                    )
                    partes = ClienteGeminiFalso.payloads[-1]["contents"][0]["parts"]
                    self.assertIn("Revisá este contenido", partes[0]["text"])
                    adjunto = partes[1]["inline_data"]
                    self.assertEqual(adjunto["mime_type"], mime_type)
                    self.assertEqual(
                        base64.b64decode(adjunto["data"]),
                        contenido
                    )

    def test_borrar_historial_elimina_resultados_estructurados(self):
        uri = f"file:cybershield_test_{id(self)}?mode=memory&cache=shared"
        conexion_persistente = sqlite3.connect(uri, uri=True)
        try:
            with patch.object(
                bot,
                "conectar_db",
                side_effect=lambda: sqlite3.connect(uri, uri=True)
            ):
                bot.inicializar_db()
                with bot.conectar_db() as conexion:
                    conexion.execute(
                        "INSERT INTO historial "
                        "(user_id, tipo, riesgo, resumen, fecha) "
                        "VALUES (7, 'Análisis', 'BAJO', 'Prueba', 'hoy')"
                    )
                    conexion.execute(
                        "INSERT INTO analisis_estructurados "
                        "(user_id, riesgo, puntuacion, resultado_json, fecha) "
                        "VALUES (7, 'BAJO', 0, '{}', 'hoy')"
                    )

                bot.eliminar_historial(7)

                with bot.conectar_db() as conexion:
                    historial = conexion.execute(
                        "SELECT COUNT(*) FROM historial WHERE user_id = 7"
                    ).fetchone()[0]
                    analisis = conexion.execute(
                        "SELECT COUNT(*) FROM analisis_estructurados "
                        "WHERE user_id = 7"
                    ).fetchone()[0]

                self.assertEqual(historial, 0)
                self.assertEqual(analisis, 0)
        finally:
            conexion_persistente.close()


if __name__ == "__main__":
    unittest.main()
