
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ResultadoAnalisis(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True
    )

    riesgo: Literal["CRÍTICO", "ALTO", "MEDIO", "BAJO"]

    puntuacion: int = Field(ge=0, le=100)

    resumen: str = Field(min_length=10, max_length=500)

    indicadores: list[str] = Field(default_factory=list)

    recomendaciones: list[str] = Field(default_factory=list)

    contiene_url: bool

    urls: list[str] = Field(default_factory=list)

    certeza: Literal["ALTA", "MEDIA", "BAJA"]
