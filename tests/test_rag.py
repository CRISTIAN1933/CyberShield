import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import bot
from modules.rag import buscar_fragmentos


class ConsultaGuiaTests(unittest.TestCase):
    def test_busca_los_tres_casos_por_nombre_y_codigo(self):
        casos = [
            ("¿Qué pasa en el caso Horizonte?", "CSH-17", "etiqueta verde"),
            ("¿A qué hora es la cita del caso Faro?", "CSH-28", "18:20"),
            ("¿Qué promete CSH-39?", "CASO MAREA", "37 minutos"),
        ]
        for pregunta, identificador, dato in casos:
            with self.subTest(pregunta=pregunta):
                fragmentos = buscar_fragmentos(pregunta)
                self.assertIn(identificador, fragmentos[0])
                self.assertIn(dato, fragmentos[0])

    def test_sin_terminos_relacionados_no_hay_resultados(self):
        self.assertEqual(buscar_fragmentos("murcielago extraterrestre"), [])

    def test_comando_envia_fragmento_a_gemini_y_responde(self):
        respuesta = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"candidates": [{"content": {"parts": [
                {"text": "En Horizonte se usa una etiqueta verde. Fuente: Guía CyberShield."}
            ]}}]},
        )
        cliente = AsyncMock()
        cliente.__aenter__.return_value = cliente
        cliente.post.return_value = respuesta
        update = SimpleNamespace()
        context = SimpleNamespace(args=["¿Qué", "pasa", "en", "Horizonte?"])
        responder = AsyncMock()

        with patch.object(bot, "GEMINI_API_KEY", "clave-prueba"), patch.object(
            bot.httpx, "AsyncClient", return_value=cliente
        ), patch.object(bot, "responder", responder):
            asyncio.run(bot.guia(update, context))

        payload = cliente.post.await_args.kwargs["json"]
        contenido = payload["contents"][0]["parts"][0]["text"]
        self.assertIn("CASO HORIZONTE", contenido)
        self.assertIn("etiqueta verde", contenido)
        self.assertIn("¿Qué pasa en Horizonte?", contenido)
        responder.assert_awaited_once_with(update, respuesta.json()["candidates"][0]["content"]["parts"][0]["text"])

    def test_no_inventa_respuesta_sin_coincidencias(self):
        responder = AsyncMock()
        context = SimpleNamespace(args=["murcielago", "extraterrestre"])
        with patch.object(bot, "GEMINI_API_KEY", "clave-prueba"), patch.object(
            bot, "responder", responder
        ), patch.object(bot.httpx, "AsyncClient") as cliente:
            asyncio.run(bot.guia(SimpleNamespace(), context))
        cliente.assert_not_called()
        self.assertIn("No encontré", responder.await_args.args[1])

    def test_archivo_ausente_notifica_error(self):
        responder = AsyncMock()
        context = SimpleNamespace(args=["Horizonte"])
        with patch.object(bot, "GEMINI_API_KEY", "clave-prueba"), patch.object(
            bot, "responder", responder
        ), patch.object(bot, "buscar_fragmentos", side_effect=FileNotFoundError):
            asyncio.run(bot.guia(SimpleNamespace(), context))
        self.assertIn("No pude leer la guía", responder.await_args.args[1])


if __name__ == "__main__":
    unittest.main()
