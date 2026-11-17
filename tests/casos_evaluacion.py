
CASOS = [
    {
        "nombre": "Suplantación bancaria",
        "texto": "URGENTE: su cuenta bancaria será bloqueada. "
                 "Ingrese su contraseña en https://banco-falso.example",
        "riesgo_esperado": "CRÍTICO"
    },
    {
        "nombre": "Código de verificación solicitado",
        "texto": "Soy del soporte de seguridad. Enviame el código SMS "
                 "para evitar el bloqueo de tu cuenta.",
        "riesgo_esperado": "CRÍTICO"
    },
    {
        "nombre": "Premio falso",
        "texto": "Ganaste un premio gratis. Para recibirlo tenés que "
                 "pagar una tasa y enviar tus datos bancarios.",
        "riesgo_esperado": "ALTO"
    },
    {
        "nombre": "Falso mensaje de entrega",
        "texto": "Tu paquete está retenido. Realizá el pago ahora "
                 "desde este enlace https://entrega-falsa.example",
        "riesgo_esperado": "ALTO"
    },
    {
        "nombre": "Enlace desconocido",
        "texto": "Me enviaron este enlace y no sé quién lo creó: "
                 "https://sitio-desconocido.example",
        "riesgo_esperado": "MEDIO"
    },
    {
        "nombre": "Aviso informativo legítimo",
        "texto": "La reunión del equipo será mañana a las 10:00. "
                 "Por favor, revisen el calendario compartido.",
        "riesgo_esperado": "BAJO"
    },
    {
        "nombre": "Conversación cotidiana",
        "texto": "Hola, ¿cómo estás? Te escribo para confirmar "
                 "si nos encontramos esta tarde.",
        "riesgo_esperado": "BAJO"
    },
    {
        "nombre": "Amenaza de suspensión y solicitud de pago",
        "texto": "Tu cuenta será suspendida inmediatamente. "
                 "Realizá una transferencia para recuperarla.",
        "riesgo_esperado": "ALTO"
    }
]
