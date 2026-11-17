
from urllib.parse import urlparse


CATEGORIAS = {
    "phishing",
    "enlace sospechoso",
    "cuenta comprometida",
    "otro"
}

URGENCIAS = {"baja", "media", "alta"}


def iniciar():
    return {
        "paso": 1,
        "datos": {}
    }


def procesar(flujo, respuesta):
    if not flujo:
        return None, "No hay un flujo activo.", False, None

    texto = respuesta.strip()
    datos = flujo["datos"]
    paso = flujo["paso"]

    if paso == 1:
        categoria = texto.lower()

        if categoria not in CATEGORIAS:
            return flujo, (
                "❌ Tipo inválido.\n\n"
                "Elegí una de estas opciones:\n"
                "• phishing\n"
                "• enlace sospechoso\n"
                "• cuenta comprometida\n"
                "• otro"
            ), False, None

        datos["categoria"] = categoria
        flujo["paso"] = 2

        return flujo, (
            "✅ Tipo registrado.\n\n"
            "2/5. Describí qué ocurrió.\n"
            "Escribí al menos 20 caracteres."
        ), False, None

    if paso == 2:
        if len(texto) < 20:
            return flujo, (
                "❌ La descripción es demasiado corta.\n"
                "Explicá un poco más lo sucedido "
                "(mínimo 20 caracteres)."
            ), False, None

        if len(texto) > 2000:
            return flujo, (
                "❌ La descripción supera los 2000 caracteres. "
                "Resumí el incidente."
            ), False, None

        datos["descripcion"] = texto
        flujo["paso"] = 3

        return flujo, (
            "3/5. ¿El incidente contiene un enlace?\n\n"
            "Enviá la URL completa o escribí NO."
        ), False, None

    if paso == 3:
        if texto.lower() == "no":
            datos["url"] = None
        else:
            try:
                parsed = urlparse(texto)

                if (
                    parsed.scheme not in ("http", "https")
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                ):
                    raise ValueError("URL inválida")

                datos["url"] = texto

            except Exception:
                return flujo, (
                    "❌ URL inválida.\n\n"
                    "Ingresá una dirección completa que comience "
                    "con https:// o http://, o escribí NO."
                ), False, None

        flujo["paso"] = 4

        return flujo, (
            "4/5. Indicá la urgencia del incidente:\n\n"
            "• baja\n"
            "• media\n"
            "• alta"
        ), False, None

    if paso == 4:
        urgencia = texto.lower()

        if urgencia not in URGENCIAS:
            return flujo, (
                "❌ Urgencia inválida.\n"
                "Respondé baja, media o alta."
            ), False, None

        datos["urgencia"] = urgencia
        flujo["paso"] = 5

        enlace = datos["url"] or "No informado"

        resumen = (
            "📋 RESUMEN DEL INCIDENTE\n\n"
            f"Tipo: {datos['categoria']}\n"
            f"Descripción: {datos['descripcion']}\n"
            f"Enlace: {enlace}\n"
            f"Urgencia: {datos['urgencia']}\n\n"
            "¿Confirmás el registro?\n"
            "Respondé CONFIRMAR o CANCELAR."
        )

        return flujo, resumen, False, None

    if paso == 5:
        decision = texto.lower()

        if decision == "confirmar":
            resultado = datos.copy()

            return None, (
                "✅ INCIDENTE REGISTRADO\n\n"
                "CyberShield recibió la información. "
                "Recordá que este registro no significa "
                "que el incidente haya sido verificado."
            ), True, resultado

        if decision == "cancelar":
            return None, (
                "❌ Registro cancelado. "
                "No se confirmó el incidente."
            ), False, None

        return flujo, (
            "❌ Respuesta inválida.\n"
            "Escribí CONFIRMAR o CANCELAR."
        ), False, None

    return None, "El flujo no es válido. Iniciá uno nuevo.", False, None
