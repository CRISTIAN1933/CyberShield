import os
import unittest
from unittest.mock import MagicMock, patch

import bot
from telegram import Update


class ConfiguracionWebhookTests(unittest.TestCase):
    def ejecutar(self, variables):
        app = MagicMock()
        builder = MagicMock()
        builder.token.return_value = builder
        builder.post_init.return_value = builder
        builder.build.return_value = app

        with patch.dict(os.environ, variables, clear=True), patch.object(
            bot, "TOKEN", "token-de-prueba"
        ), patch.object(bot.Application, "builder", return_value=builder):
            bot.main()
        return app

    def test_sin_url_usa_polling_local(self):
        app = self.ejecutar({})
        app.run_polling.assert_called_once_with(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        app.run_webhook.assert_not_called()

    def test_render_usa_webhook_y_puerto_asignado(self):
        app = self.ejecutar({
            "RENDER_EXTERNAL_URL": "https://bot.example/",
            "PORT": "12345",
            "WEBHOOK_SECRET": "secreto_de_prueba",
        })
        app.run_webhook.assert_called_once_with(
            listen="0.0.0.0",
            port=12345,
            url_path="telegram",
            webhook_url="https://bot.example/telegram",
            secret_token="secreto_de_prueba",
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        app.run_polling.assert_not_called()

    def test_url_explicita_tiene_prioridad(self):
        app = self.ejecutar({
            "WEBHOOK_URL": "https://custom.example",
            "RENDER_EXTERNAL_URL": "https://render.example",
            "WEBHOOK_SECRET": "secreto",
        })
        self.assertEqual(
            app.run_webhook.call_args.kwargs["webhook_url"],
            "https://custom.example/telegram",
        )

    def test_rechaza_secreto_ausente_o_invalido(self):
        for secret in ("", "espacios no permitidos", "a" * 257):
            with self.subTest(secret=secret):
                with self.assertRaisesRegex(RuntimeError, "WEBHOOK_SECRET"):
                    self.ejecutar({
                        "RENDER_EXTERNAL_URL": "https://bot.example",
                        "WEBHOOK_SECRET": secret,
                    })

    def test_rechaza_url_insegura_o_con_ruta(self):
        for url in ("http://bot.example", "https://bot.example/ruta"):
            with self.subTest(url=url):
                with self.assertRaisesRegex(RuntimeError, "WEBHOOK_URL"):
                    self.ejecutar({
                        "WEBHOOK_URL": url,
                        "WEBHOOK_SECRET": "secreto",
                    })


if __name__ == "__main__":
    unittest.main()
