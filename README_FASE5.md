# CyberDefense Fase 5

Conserva `cyberdefense.db` y `.venv` de tu instalación previa. Sustituye los archivos de código por los de esta versión. Instala requisitos con `pip install -r requirements.txt`. La nueva API requiere `CYBERDEFENSE_MANBA_KEY`, la misma variable que utilizará PHP. Primera ejecución con `python app.py` crea la tabla `connected_systems` y registra MANBA. Entra con admin y visita `http://127.0.0.1:5000/sistemas`.

**No uses el servidor Flask de desarrollo en producción.** El endpoint responde a POST JSON firmado HMAC-SHA256 (firma sobre `timestamp + '.' + cuerpo exacto`), tiempo máximo de 90 segundos y eventos únicos. No transmite contraseñas ni datos académicos.

Lee `../MANBA_Integracion/README_INTEGRACION.md` para configurar Apache/PHP y la prueba.
