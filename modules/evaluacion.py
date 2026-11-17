
import asyncio
import json
from datetime import datetime
from pathlib import Path

from bot import analizar_con_gemini
from tests.casos_evaluacion import CASOS


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(exist_ok=True)


async def ejecutar_evaluacion():
    resultados = []

    total = len(CASOS)
    correctos = 0
    errores = 0

    print("\n" + "=" * 65)
    print("CYBERSHIELD - EVALUACIÓN DE CALIDAD")
    print("=" * 65)

    for numero, caso in enumerate(CASOS, start=1):
        print(f"\n[{numero}/{total}] {caso['nombre']}")

        resultado = await analizar_con_gemini(caso["texto"])

        if resultado is None:
            errores += 1

            registro = {
                "caso": caso["nombre"],
                "esperado": caso["riesgo_esperado"],
                "obtenido": None,
                "correcto": False,
                "error": "No se obtuvo una respuesta válida."
            }

        else:
            obtenido = resultado.riesgo
            correcto = obtenido == caso["riesgo_esperado"]

            if correcto:
                correctos += 1

            registro = {
                "caso": caso["nombre"],
                "esperado": caso["riesgo_esperado"],
                "obtenido": obtenido,
                "correcto": correcto,
                "puntuacion": resultado.puntuacion,
                "resumen": resultado.resumen,
                "indicadores": resultado.indicadores
            }

        resultados.append(registro)

        estado = "CORRECTO" if registro["correcto"] else "FALLIDO"

        print(f"Esperado: {registro['esperado']}")
        print(f"Obtenido: {registro['obtenido']}")
        print(f"Resultado: {estado}")

    porcentaje = (correctos / total) * 100 if total else 0
    porcentaje_error = (errores / total) * 100 if total else 0
    porcentaje_incorrectos = (
        ((total - correctos - errores) / total) * 100
        if total else 0
    )

    informe = {
        "fecha": datetime.now().isoformat(),
        "total_casos": total,
        "correctos": correctos,
        "incorrectos": total - correctos - errores,
        "errores_ejecucion": errores,
        "porcentaje_acierto": round(porcentaje, 2),
        "porcentaje_incorrectos": round(porcentaje_incorrectos, 2),
        "porcentaje_error_ejecucion": round(porcentaje_error, 2),
        "resultados": resultados
    }

    nombre = datetime.now().strftime(
        "evaluacion_%Y%m%d_%H%M%S.json"
    )

    ruta = REPORTS_DIR / nombre

    ruta.write_text(
        json.dumps(informe, ensure_ascii=False, indent=4),
        encoding="utf-8"
    )

    print("\n" + "=" * 65)
    print("RESUMEN DE EVALUACIÓN")
    print("=" * 65)
    print(f"Casos ejecutados: {total}")
    print(f"Correctos: {correctos}")
    print(f"Incorrectos: {total - correctos - errores}")
    print(f"Errores de ejecución: {errores}")
    print(f"Porcentaje de acierto: {porcentaje:.2f}%")
    print(f"Porcentaje de errores de ejecución: {porcentaje_error:.2f}%")
    print(f"\nReporte generado: {ruta}")
    print("=" * 65)

    return informe


if __name__ == "__main__":
    asyncio.run(ejecutar_evaluacion())
