# CyberDefense Fase 4 — Reportes y modo exposicion

## Instalacion en Windows
1. Detener Flask (`Ctrl+C`). Hacer copia de seguridad completa del proyecto actual.
2. Copiar `app.py`, `templates/`, `static/` y `requirements.txt` de este ZIP sobre el proyecto actual.
3. NO reemplazar `cyberdefense.db`, NO borrar `.venv`, NO cambiar tu clave de administrador.
4. En PowerShell, desde la carpeta CyberDefense:
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```
5. Entra como admin a http://127.0.0.1:5000/dashboard. Accede a Reportes y Modo exposicion.

## Nuevas funciones
- `GET /reportes`: recuentos y grafica de simulaciones de SQLite.
- `GET /api/reports/summary`: historial de 100 simulaciones (solo admin).
- `GET /export/reporte.pdf`: PDF de resultados (solo admin).
- `GET /demostracion`: guion interactivo de 5 pasos.
- `GET /export/events.csv`: exportacion CSV de Fase 2, conservada.

## Alcance
Los eventos del laboratorio son sinteticos. El reporte separa alertas reales del login de alertas del laboratorio. Los historiales web muestran las 100 ejecuciones mas recientes, mientras los contadores utilizan toda la base de datos.
No exponer el servidor a Internet; esta configurado para 127.0.0.1.
