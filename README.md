# CyberDefense — Fase 2

Laboratorio local de protección de accesos web, con dashboard SOC, gráfica de actividad de 12 horas (UTC), filtros, gravedad ilustrativa por evento y CSV.

## Ejecutar en Windows

Desde la carpeta CyberDefense:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Abrir http://127.0.0.1:5000. Cuenta `demo` / `Demo123!`. Cuenta `admin` con clave aleatoria **solo la primera vez** (o `CYBERDEFENSE_ADMIN_PASSWORD` si se establece antes de crear la BD).

### MUY IMPORTANTE al actualizar desde Fase 1

**Conserva el archivo `cyberdefense.db` de tu carpeta Fase 1**: contiene los registros, usuarios y contraseña de administrador. Si sustituyes el código, copia los archivos nuevos a tu carpeta actual sin borrar tu BD. Detén Flask con Ctrl+C antes de actualizar y haz una copia de respaldo de esa BD.

Si Flask corre con una base nueva, se creará otra contraseña de admin que solo aparece al primer inicio.

## Pruebas

1. Ingresa con `admin` para abrir `/dashboard`.
2. En una ventana privada provoca cinco fallos con usuario `demo` en menos de 60 segundos; observa la alerta.
3. Intenta una sexta vez durante el bloqueo para aumentar «Intentos bloqueados».
4. Verifica gráfica, filtro por evento y botón Exportar CSV.

El contador «Intentos bloqueados» contabiliza solicitudes **durante** un bloqueo, no cantidad de bloqueos activados. La categoría «Gravedad» es una clasificación pedagógica, no un motor de inteligencia de amenazas. El conteo de bloqueos activos se basa en la tabla limits.

Este proyecto solo monitorea SU PROPIA aplicación. No es un cortafuegos ni analiza red externa. Ejecutar exclusivamente en 127.0.0.1 en entornos de laboratorio, nunca en Internet con el servidor de desarrollo Flask.
