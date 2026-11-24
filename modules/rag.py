import math
import re
import unicodedata
from pathlib import Path


DOCUMENTO = Path(__file__).resolve().parent.parent / "documentos" / "guia_cybershield.txt"

PALABRAS_COMUNES = {
    "a", "al", "algo", "con", "cual", "cuales", "de", "del", "el",
    "en", "es", "esta", "este", "guia", "la", "las", "lo", "los",
    "me", "por", "que", "se", "segun", "sobre", "un", "una", "y",
}


def palabras(texto: str) -> set[str]:
    normalizado = unicodedata.normalize("NFKD", texto.casefold())
    sin_tildes = "".join(c for c in normalizado if not unicodedata.combining(c))
    return {
        palabra for palabra in re.findall(r"[a-z0-9]+", sin_tildes)
        if len(palabra) > 1 and palabra not in PALABRAS_COMUNES
    }


def buscar_fragmentos(pregunta: str, limite: int = 3) -> list[str]:
    contenido = DOCUMENTO.read_text(encoding="utf-8")
    fragmentos = [fragmento.strip() for fragmento in contenido.split("\n\n") if fragmento.strip()]
    consulta = palabras(pregunta)
    if not consulta:
        return []

    terminos = [palabras(fragmento) for fragmento in fragmentos]
    frecuencia = {
        palabra: sum(palabra in conjunto for conjunto in terminos)
        for palabra in consulta
    }
    resultados = []
    for fragmento, conjunto in zip(fragmentos, terminos):
        coincidencias = consulta & conjunto
        puntuacion = sum(
            math.log((len(fragmentos) + 1) / (frecuencia[palabra] + 1)) + 1
            for palabra in coincidencias
        )
        if puntuacion:
            resultados.append((puntuacion, fragmento))

    resultados.sort(key=lambda resultado: resultado[0], reverse=True)
    return [fragmento for _, fragmento in resultados[:limite]]
