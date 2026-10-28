# CyberDefense NEXORA — preparado para Render

## Configuración del servicio web en Render

- **Branch:** `main`
- **Root Directory:** vacío si `app.py` está en la raíz del repositorio; si mantuviste una carpeta `CyberDefense/`, escribe `CyberDefense`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn --bind 0.0.0.0:$PORT --workers 1 app:app`
- **Plan:** Free para DEMOSTRACIÓN temporal, no producción con registros permanentes

### Variables de entorno (Render > Environment)
- `CYBERDEFENSE_SECRET`: pulsar Generate, conservar estable
- `CYBERDEFENSE_ADMIN_PASSWORD`: contraseña privada fuerte, mínimo 12 caracteres, **antes del primer deploy**
- `CYBERDEFENSE_DEMO_PASSWORD`: contraseña privada diferente para el trabajador `demo`; no usar `Demo123!`

**No** envíes secretos al chat, repositorio o capturas. Esta app no publica usuarios/contraseñas hasta que se configuren mediante variables de entorno. Si ya has usado SQLite con usuarios anteriores, no publiques el archivo DB anterior.

### Persistencia
SQLite está en `cyberdefense.db` en la carpeta de la aplicación por defecto. **Render Free usa un sistema de archivos efímero: cada reinicio o redeploy puede perder ventas, bloqueos, usuarios e incidentes.** Para datos permanentes se requiere otro diseño (p. ej. migrar a PostgreSQL) o disco persistente en un plan compatible. No sirve añadir solo `DATABASE_URL` sin migrar consultas.

`CYBERDEFENSE_DB_PATH` permite elegir una ruta SQLite cuando haya un volumen persistente montado; se debe establecer antes de iniciar la aplicación, por ejemplo `/var/data/cyberdefense.db`. **No crea un disco** por sí sola. Usa un único trabajador Gunicorn para evitar contención de SQLite.

### Actualizar GitHub
1. Copia `app.py`, `requirements.txt`, `render.yaml`, `.gitignore`, `templates/` y `static/` del ZIP al directorio de tu repositorio.
2. No copies `cyberdefense.db` ni `.venv`.
3. Desde la carpeta que contiene `app.py` ejecuta `git add . && git commit -m "Preparar CyberDefense para Render" && git push origin main`.
4. En Render, completa los comandos y variables descritos arriba. Deploy.

### Avisos
- Al publicar en internet, **la URL será accesible para cualquiera que la conozca**, aunque las rutas administrativas requieren autenticación. No uses datos reales.
- La protección por IP y usuario de esta demo puede variar detrás de proxies; no equivale a un WAF ni identifica inequívocamente celulares.
- Mantén `CYBERDEFENSE_SECRET` estable; cambiarlo invalida sesiones.
