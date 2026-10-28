# CyberDefense — Fase 3

## Requisitos
Python 3, Flask (ver `requirements.txt`).

## Instalación segura sobre Fase 2
1. Detén Flask (`Ctrl+C`).
2. Haz una copia de seguridad de tu carpeta CyberDefense, en especial `cyberdefense.db`.
3. Copia `app.py`, `templates/` y `static/` desde este ZIP a tu carpeta existente, reemplazando archivos.
4. **No elimines ni reemplaces** `cyberdefense.db` ni `.venv/`.
5. Ejecuta `python app.py` desde tu entorno virtual.
6. Inicia sesión como `admin` y entra al enlace **Laboratorio de amenazas** en el menú.

## Pruebas
- Ejecuta cada escenario y comprueba el resultado.
- Regresa al Dashboard: las alertas y los eventos `lab_*` deben aparecer en el historial.
- Prueba la exportación CSV para revisar las evidencias.
- Solo el administrador puede abrir el laboratorio y ejecutar pruebas.

**Límites:** son simulaciones educativas, no ataques reales. El escenario SQL usa consultas parametrizadas, XSS se muestra como texto, y fuerza bruta y control de acceso simulan decisiones sin alterar usuarios ni restricciones reales.
