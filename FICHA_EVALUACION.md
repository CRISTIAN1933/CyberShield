# Ficha del bot — CyberShield

Sistemas Inteligentes Aplicados · ITU · UNCuyo

Los cambios respecto de la propuesta original del Hito 1 están en **negrita**.

## 1. Propuesta del Hito 1, actualizada

| Dato | Propuesta actual |
|---|---|
| Nombre del equipo | CYBERSHIELD |
| Usuario destinatario | Personas que utilizan Internet, estudiantes y usuarios que desean identificar amenazas digitales, prevenir estafas y proteger su información personal. |
| Problema que resuelve | Ayuda a reconocer posibles intentos de phishing, mensajes fraudulentos y enlaces maliciosos. Sin esta herramienta, los usuarios deben evaluar manualmente los mensajes y recurrir a diferentes servicios para comprobar su seguridad. |
| Personalidad y tono | Profesional, preventivo, amigable y educativo. Se comunica en español mediante explicaciones claras, recomendaciones prácticas y advertencias cuando identifica posibles riesgos. |
| Función propia 1 | Análisis de mensajes, correos y textos sospechosos mediante Google Gemini. Identifica indicadores de phishing, ingeniería social, suplantación de identidad y posibles estafas, generando un informe con nivel de riesgo y recomendaciones. **También analiza fotos y notas de voz recibidas en Telegram cuando está activo el modo `/analizar`.** |
| Función propia 2 | Verificación de indicadores mediante VirusTotal. **Además de enlaces, admite dominios, direcciones IP y hashes; también permite enviar archivos para consultar o realizar un análisis con VirusTotal.** |
| Función propia 3 (opcional) | Gestión del historial mediante SQLite. Permite consultar los últimos diez registros, conocer sus niveles de riesgo y eliminar el historial de análisis, los resultados estructurados y la memoria de conversación. También ofrece consejos de seguridad digital. |
| Capacidad de análisis | Analiza mensajes y enlaces para identificar indicadores sospechosos, clasificar niveles de riesgo, extraer señales de ingeniería social y generar resúmenes explicativos mediante inteligencia artificial. **El resultado estructurado se valida con Pydantic; el modo `/analizar` también acepta imágenes y audio. Si Gemini no está disponible, los mensajes de texto pueden recibir un análisis local preliminar.** |
| Módulo avanzado 1 | Evaluación inteligente de contenido mediante Google Gemini, combinada con un análisis preliminar local basado en patrones e indicadores de seguridad. **Gemini también interpreta el contenido de fotos y notas de voz enviadas durante el modo de análisis.** |
| Módulo avanzado 2 | **Flujo guiado `/reporte` para registrar incidentes en cinco pasos, con validaciones y confirmación antes de guardar el reporte en SQLite.** También hay comandos para analizar mensajes, verificar indicadores y consultar resultados. |
| Ejemplo de conversación | El usuario activa `/analizar` y envía un texto sospechoso; CyberShield devuelve riesgo, puntuación, certeza, indicadores y recomendaciones. **También puede enviar una foto o una nota de voz en ese modo.** |

## 2. Datos para la evaluación

| Dato | Respuesta del equipo |
|---|---|
| Usuario de Telegram del bot | **Completar con el usuario real, incluido `@`.** No está configurado ni documentado en el código del proyecto. |
| Comandos | `/start` — inicia el bot y muestra sus funciones.<br>`/help` — muestra la ayuda y los pasos de uso.<br>`/analizar` — activa el análisis de texto, fotos o notas de voz.<br>`/verificar` — consulta un indicador en VirusTotal; también acepta el indicador como argumento.<br>`/reporte` — inicia el registro guiado de un incidente.<br>`/seguridad` — muestra un consejo de seguridad.<br>`/historial` — consulta los últimos diez registros.<br>`/borrarhistorial` — elimina el historial de análisis, los resultados estructurados y la memoria de conversación.<br>`/privacidad` — informa qué datos se procesan y dónde.<br>`/cancelar` — cancela el modo o flujo activo.<br>`/acerca` — muestra información y tecnologías del bot. |
| Pregunta de ejemplo para la función propia 1 | “Me llegó este mensaje: «Tu cuenta será bloqueada hoy. Verificá tus datos en https://banco-seguro.example». ¿Parece phishing?” |
| Pregunta de ejemplo para la función propia 2 | “¿Podés comprobar con VirusTotal este enlace: https://example.com?” |
| Análisis estructurado | Se activa con `/analizar` y luego se envía un texto, una foto o una nota de voz. Gemini genera riesgo, puntuación, resumen, indicadores, recomendaciones, URLs y certeza; Pydantic valida el resultado. Se guarda como JSON en `data/cybershield.db`, tabla `analisis_estructurados`; también se registra un resumen en `historial` y el resultado se muestra en Telegram. |
| Dato del módulo avanzado 1 | **Multimodalidad:** entiende fotos y notas de voz durante el modo `/analizar`. El contenido se envía a Gemini para su interpretación. Límite del bot: 14 MB por archivo. Requiere que Gemini esté configurado. |
| Dato del módulo avanzado 2 | **Flujo guiado:** se inicia con `/reporte`. Pasos: 1) categoría (`phishing`, `enlace sospechoso`, `cuenta comprometida` u `otro`); 2) descripción de 20 a 2000 caracteres; 3) URL completa HTTP/HTTPS o `NO`; 4) urgencia (`baja`, `media` o `alta`); 5) confirmar o cancelar. Las respuestas se validan en cada paso y el reporte confirmado se guarda en SQLite, tabla `reportes_guiados`. |
| Dónde funciona el bot | En una computadora del equipo, usando Telegram en modo polling. **El código también admite webhooks para Render, pero el despliegue debe completarse y verificarse antes de declararlo en funcionamiento.** |
| Cómo se reinicia | Detenerlo con `Ctrl+C` en la terminal y volver a iniciarlo desde la carpeta del proyecto con `.\.venv\Scripts\python.exe bot.py`. |
| Módulos no utilizados | No usa RAG. El despliegue con webhooks requiere configurar y verificar el servicio en Render. |
| Evaluación | Script: `modules/evaluacion.py`. Casos: `tests/casos_evaluacion.py`. El archivo de casos contiene **8 casos**. Ejecutar desde la carpeta del proyecto con `.\.venv\Scripts\python.exe -m modules.evaluacion`; requiere la configuración de Gemini para obtener resultados de IA. |

**Antes de entregar:** completar el usuario real de Telegram del bot; ese dato no se puede deducir de los archivos del proyecto.
