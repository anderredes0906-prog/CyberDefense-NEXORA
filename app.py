import os
import csv
import io
import sqlite3
import secrets
import time
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from datetime import datetime as local_datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort, Response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('CYBERDEFENSE_DB_PATH', str(ROOT / 'cyberdefense.db')))
app = Flask(__name__)
IS_RENDER = bool(os.environ.get('RENDER'))
IS_PUBLIC = IS_RENDER or os.environ.get('CYBERDEFENSE_PUBLIC') == '1'
if IS_PUBLIC and not os.environ.get('CYBERDEFENSE_SECRET'):
    raise RuntimeError('Configura CYBERDEFENSE_SECRET en Render antes de iniciar.')
app.secret_key = os.environ.get('CYBERDEFENSE_SECRET') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=IS_PUBLIC)
LIMIT = 5
WINDOW = 60
BLOCK_SECONDS = 60
COMPANY_LIMIT = 3
COMPANY_WINDOW = 120
COMPANY_BLOCK_SECONDS = 300


def now():
    return int(time.time())


def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, username TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS limits (identity TEXT PRIMARY KEY, first_failure INTEGER NOT NULL, failures INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0)')
        c.execute('CREATE TABLE IF NOT EXISTS company_limits (identity TEXT PRIMARY KEY, username TEXT NOT NULL, source TEXT NOT NULL, first_attempt INTEGER NOT NULL, attempts INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0)')
        c.execute('CREATE TABLE IF NOT EXISTS ventas (id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, empleado TEXT NOT NULL, producto TEXT NOT NULL, cantidad INTEGER NOT NULL, precio_centavos INTEGER NOT NULL, total_centavos INTEGER NOT NULL)')
        if not c.execute('SELECT 1 FROM users WHERE username=?', ('demo',)).fetchone():
            # Nunca publicar una cuenta con contraseña conocida.
            demo_password = os.environ.get('CYBERDEFENSE_DEMO_PASSWORD')
            if demo_password:
                c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                          ('demo', generate_password_hash(demo_password), 'user'))
            elif not IS_PUBLIC:
                c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                          ('demo', generate_password_hash('Demo123!'), 'user'))
        if not c.execute('SELECT 1 FROM users WHERE username=?', ('admin',)).fetchone():
            password = os.environ.get('CYBERDEFENSE_ADMIN_PASSWORD')
            if IS_PUBLIC and (not password or len(password) < 12):
                raise RuntimeError('Configura CYBERDEFENSE_ADMIN_PASSWORD (minimo 12 caracteres) en Render.')
            if not password:
                password = secrets.token_urlsafe(15)
                print('\n' + '='*60 + '\nCLAVE ADMIN INICIAL (guardar): ' + password + '\n' + '='*60 + '\n')
            c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)', ('admin', generate_password_hash(password), 'admin'))


def event(c, username, source, kind, detail):
    c.execute('INSERT INTO events(created,username,source,kind,detail) VALUES(?,?,?,?,?)', (now(), username[:80], source, kind, detail))


def admin_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('home'))
        return fn(*args, **kwargs)
    return wrapped


def company_identity():
    # El IP es el observado por Flask; no confiamos en cabeceras X-Forwarded-For del cliente.
    return (request.remote_addr or 'local') + ':' + str(session.get('username', '')).lower()


def company_block_remaining():
    if session.get('role') == 'admin' or 'username' not in session:
        return 0
    with db() as c:
        row = c.execute('SELECT blocked_until FROM company_limits WHERE identity=?', (company_identity(),)).fetchone()
        return max(0, row['blocked_until'] - now()) if row else 0


def register_company_denial():
    current = now()
    identity = company_identity()
    username = session.get('username', 'desconocido')
    source = request.remote_addr or 'local'
    with db() as c:
        old = c.execute('SELECT * FROM company_limits WHERE identity=?', (identity,)).fetchone()
        if old and old['blocked_until'] > current:
            event(c, username, source, 'bloqueado', 'NEXORA: acceso rechazado durante el bloqueo')
            return True
        if not old or current - old['first_attempt'] >= COMPANY_WINDOW:
            attempts, first = 1, current
        else:
            attempts, first = old['attempts'] + 1, old['first_attempt']
        blocked_until = current + COMPANY_BLOCK_SECONDS if attempts >= COMPANY_LIMIT else 0
        c.execute('INSERT INTO company_limits(identity,username,source,first_attempt,attempts,blocked_until) VALUES(?,?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET username=excluded.username,source=excluded.source,first_attempt=excluded.first_attempt,attempts=excluded.attempts,blocked_until=excluded.blocked_until', (identity,username,source,first,attempts,blocked_until))
        event(c, username, source, 'acceso_denegado', f'NEXORA: intento {attempts}/{COMPANY_LIMIT} a administración sin permisos')
        if blocked_until:
            event(c, username, source, 'alerta', f'NEXORA: bloqueo del portal por {COMPANY_BLOCK_SECONDS // 60} minutos')
            return True
    return False


@app.before_request
def restrict_company():
    # Se limita el portal empresarial (incluida su portada), no el panel SOC del administrador.
    if request.path.startswith('/empresa') and company_block_remaining():
        with db() as c:
            event(c, session.get('username',''), request.remote_addr or 'local', 'bloqueado', 'NEXORA: portal empresarial restringido')
        return render_template('empresa_bloqueada.html', seconds=company_block_remaining()), 403


@app.before_request
def csrf_guard():
    if request.method == 'POST':
        supplied = request.form.get('csrf_token', '')
        if not secrets.compare_digest(str(session.get('csrf_token', '')), supplied) or not supplied:
            abort(400, 'Token CSRF inválido')


@app.context_processor
def add_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(24)
    return {'csrf_token': session['csrf_token']}


@app.route('/')
def home():
    return render_template('login.html')


@app.post('/login')
def login():
    username = request.form.get('username', '').strip()[:80]
    password = request.form.get('password', '')
    source = request.remote_addr or 'local'
    identity = source + ':' + username.lower()
    current = now()
    with db() as c:
        r = c.execute('SELECT * FROM limits WHERE identity=?', (identity,)).fetchone()
        if r and r['blocked_until'] > current:
            event(c, username, source, 'bloqueado', 'Acceso rechazado por bloqueo temporal')
            flash(f'Acceso temporalmente restringido. Intenta nuevamente en {r["blocked_until"]-current} segundos.', 'danger')
            return redirect(url_for('home'))
        user = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            c.execute('DELETE FROM limits WHERE identity=?', (identity,))
            event(c, username, source, 'exitoso', 'Inicio de sesión válido')
            session.clear()
            session['username'] = username
            session['role'] = user['role']
            session['csrf_token'] = secrets.token_hex(24)
            return redirect(url_for('dashboard' if user['role'] == 'admin' else 'welcome'))
        if not r or current - r['first_failure'] >= WINDOW:
            failures, first = 1, current
        else:
            failures, first = r['failures'] + 1, r['first_failure']
        blocked = current + BLOCK_SECONDS if failures >= LIMIT else 0
        c.execute('INSERT INTO limits(identity,first_failure,failures,blocked_until) VALUES(?,?,?,?) ON CONFLICT(identity) DO UPDATE SET first_failure=excluded.first_failure, failures=excluded.failures, blocked_until=excluded.blocked_until', (identity, first, failures, blocked))
        event(c, username, source, 'fallido', 'Credenciales inválidas')
        if blocked:
            event(c, username, source, 'alerta', 'Cinco intentos fallidos: bloqueo de 60 segundos')
            flash('Alerta de seguridad: acceso restringido durante 60 segundos.', 'danger')
        else:
            flash('Usuario o contraseña incorrectos.', 'warning')
    return redirect(url_for('home'))


@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('home'))
    return render_template('welcome.html')


@app.route('/dashboard')
@admin_only
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/events')
@admin_only
def api_events():
    with db() as c:
        rows = c.execute('SELECT created, username, source, kind, detail FROM events ORDER BY id DESC LIMIT 50').fetchall()
        counts = {r['kind']: r['total'] for r in c.execute('SELECT kind, COUNT(*) AS total FROM events GROUP BY kind')}
    return jsonify({'counts': counts, 'events': [{**dict(r), 'time': datetime.fromtimestamp(r['created'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} for r in rows]})


@app.get('/api/overview')
@admin_only
def api_overview():
    current = now()
    start = current - 23 * 3600
    with db() as c:
        grouped = c.execute('SELECT (created / 3600) * 3600 AS hour, kind, COUNT(*) AS total FROM events WHERE created >= ? GROUP BY hour, kind', (start,)).fetchall()
        recent_alerts = c.execute("SELECT created, username, source, detail FROM events WHERE kind = 'alerta' ORDER BY id DESC LIMIT 8").fetchall()
        unique_sources = c.execute('SELECT COUNT(DISTINCT source) FROM events').fetchone()[0]
        active_blocks = c.execute('SELECT COUNT(*) FROM limits WHERE blocked_until > ?', (current,)).fetchone()[0]
    buckets = {hour: {'hour': datetime.fromtimestamp(hour, timezone.utc).strftime('%H:%M'), 'fallido': 0, 'exitoso': 0, 'alerta': 0, 'bloqueado': 0} for hour in range((current // 3600 - 11) * 3600, (current // 3600 + 1) * 3600, 3600)}
    for r in grouped:
        if r['hour'] in buckets and r['kind'] in buckets[r['hour']]:
            buckets[r['hour']][r['kind']] = r['total']
    return jsonify({'timeline': list(buckets.values()), 'active_blocks': active_blocks, 'unique_sources': unique_sources, 'recent_alerts': [{**dict(r), 'time': datetime.fromtimestamp(r['created'], timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} for r in recent_alerts]})


@app.get('/export/events.csv')
@admin_only
def export_events():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Fecha UTC', 'Usuario', 'Origen', 'Evento', 'Detalle'])
    with db() as c:
        for r in c.execute('SELECT created, username, source, kind, detail FROM events ORDER BY id DESC LIMIT 10000'):
            writer.writerow([datetime.fromtimestamp(r['created'], timezone.utc).isoformat(), r['username'], r['source'], r['kind'], r['detail']])
    data = '﻿' + output.getvalue()
    return Response(data, mimetype='text/csv; charset=utf-8', headers={'Content-Disposition': 'attachment; filename=cyberdefense_incidentes.csv', 'Cache-Control': 'no-store'})


# Laboratorio educativo: solo muestras sinteticas y defensas dentro de CyberDefense.
# Las simulaciones NO ejecutan SQL malicioso, JavaScript ni ataques de red.
LAB_CASES = {
    'fuerza_bruta': {
        'title': 'Fuerza bruta', 'kind': 'lab_fuerza_bruta',
        'test': 'Se simulan 5 intentos de acceso fallidos con una cuenta ficticia.',
        'detection': 'Regla: 5 fallos en 60 segundos.',
        'defense': 'El acceso se restringiria temporalmente; las cuentas reales no se modifican.',
    },
    'sql': {
        'title': 'Inyeccion SQL', 'kind': 'lab_sql',
        'test': "Entrada de ejemplo: ' OR '1'='1 (solo texto).",
        'detection': 'Se identifica un patron de entrada sospechoso.',
        'defense': 'Se consulta SQLite con parametros en lugar de concatenar la entrada.',
    },
    'xss': {
        'title': 'Cross-Site Scripting (XSS)', 'kind': 'lab_xss',
        'test': 'Se introduce una cadena que parece una etiqueta HTML con script.',
        'detection': 'Se reconoce una entrada que podria introducir contenido activo.',
        'defense': 'La cadena se presenta como texto escapado, no como HTML ejecutable.',
    },
    'acceso': {
        'title': 'Acceso no autorizado', 'kind': 'lab_acceso',
        'test': 'Una identidad ficticia sin rol de administrador solicita un recurso restringido.',
        'detection': 'El control de roles identifica permisos insuficientes.',
        'defense': 'El recurso se deniega con estado 403 en la evaluacion simulada.',
    },
}


@app.get('/laboratorio')
@admin_only
def laboratorio():
    return render_template('laboratorio.html', cases=LAB_CASES)


@app.post('/api/lab/simulate')
@admin_only
def lab_simulate():
    name = request.form.get('scenario', '')
    case = LAB_CASES.get(name)
    if case is None:
        return jsonify({'error': 'Escenario no valido'}), 400
    # Pruebas completamente locales y sinteticas, sin tocar cuentas o limites reales.
    evidence = {}
    if name == 'fuerza_bruta':
        evidence = {'intentos': 5, 'umbral': LIMIT, 'resultado': 'Bloqueo de laboratorio activado (simulado)'}
    elif name == 'sql':
        entry = "' OR '1'='1"
        with db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS lab_catalog (name TEXT PRIMARY KEY)')
            c.execute('INSERT OR IGNORE INTO lab_catalog(name) VALUES(?)', ('equipo-demo',))
            rows = c.execute('SELECT name FROM lab_catalog WHERE name = ?', (entry,)).fetchall()
        evidence = {'entrada': entry, 'coincidencias': len(rows), 'resultado': 'Consulta parametrizada: no se altero la condicion SQL'}
    elif name == 'xss':
        entry = '<script>alert("demo")</script>'
        # Solo se devuelve texto JSON. El cliente lo coloca con textContent.
        evidence = {'entrada': entry, 'resultado': 'Texto mostrado sin ejecutarse (textContent)'}
    elif name == 'acceso':
        allowed = 'admin' in {'user'}
        evidence = {'rol_ficticio': 'user', 'http_simulado': 200 if allowed else 403,
                    'resultado': 'Acceso denegado por control de roles'}
    with db() as c:
        event(c, 'laboratorio', 'simulacion-local', case['kind'], case['test'])
        event(c, 'laboratorio', 'simulacion-local', 'alerta', 'Laboratorio: ' + case['title'] + ' detectado y contenido')
    return jsonify({'ok': True, 'scenario': name, 'title': case['title'],
                    'test': case['test'], 'detection': case['detection'],
                    'defense': case['defense'], 'evidence': evidence})




# Fase 4: estadisticas de simulaciones, historial y exportacion PDF.
# Las cifras proceden de los eventos guardados (no se generan datos inventados).
LAB_NAMES = {
    'lab_fuerza_bruta': 'Fuerza bruta', 'lab_sql': 'Inyeccion SQL',
    'lab_xss': 'XSS', 'lab_acceso': 'Acceso no autorizado',
}


def lab_summary():
    with db() as c:
        rows = c.execute("""SELECT kind, COUNT(*) AS total FROM events WHERE kind IN (?,?,?,?) GROUP BY kind""", tuple(LAB_NAMES)).fetchall()
        history = c.execute("""SELECT id, created, kind, detail FROM events WHERE kind IN (?,?,?,?) ORDER BY id DESC LIMIT 100""", tuple(LAB_NAMES)).fetchall()
        total_events = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        actual_alerts = c.execute("SELECT COUNT(*) FROM events WHERE kind='alerta' AND detail NOT LIKE 'Laboratorio:%'").fetchone()[0]
    counts = {name: 0 for name in LAB_NAMES}
    counts.update({r['kind']: r['total'] for r in rows})
    items = [{'id': r['id'], 'time': datetime.fromtimestamp(r['created'], timezone.utc).strftime('%Y-%m-%d %H:%M UTC'), 'kind': r['kind'], 'title': LAB_NAMES[r['kind']], 'detail': r['detail']} for r in history]
    return {'counts': counts, 'total_simulations': sum(counts.values()), 'total_events': total_events,
            'real_alerts': actual_alerts, 'history': items, 'history_limit': 100}


@app.get('/reportes')
@admin_only
def reportes():
    return render_template('reportes.html')


@app.get('/api/reports/summary')
@admin_only
def api_report_summary():
    response = jsonify(lab_summary())
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/export/reporte.pdf')
@admin_only
def export_pdf():
    summary = lab_summary()
    out = io.BytesIO()
    pdf = canvas.Canvas(out, pagesize=A4, pageCompression=1)
    w, h = A4
    pdf.setTitle('CyberDefense - Informe del laboratorio')
    pdf.setAuthor('CyberDefense - Proyecto educativo')
    pdf.setFillColor(HexColor('#0b1d32'))
    pdf.rect(0, h-108, w, 108, fill=1, stroke=0)
    pdf.setFillColor(HexColor('#4cceff'))
    pdf.setFont('Helvetica-Bold', 23)
    pdf.drawString(42, h-56, 'CYBERDEFENSE')
    pdf.setFillColor(HexColor('#d5e9ff'))
    pdf.setFont('Helvetica', 10)
    pdf.drawString(42, h-78, 'Informe de seguridad | Laboratorio educativo local')
    y = h - 138
    pdf.setFillColor(HexColor('#243348'))
    pdf.setFont('Helvetica', 10)
    pdf.drawString(42, y, 'Fecha de generacion (UTC): ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M'))
    y -= 32
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(42, y, 'Resumen general')
    y -= 25
    pdf.setFont('Helvetica', 11)
    for label, val in [('Simulaciones registradas', summary['total_simulations']), ('Eventos de la aplicacion', summary['total_events']), ('Alertas de acceso reales (sin alertas del laboratorio)', summary['real_alerts'])]:
        pdf.drawString(48, y, f'{label}: {val}')
        y -= 20
    y -= 15
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(42, y, 'Simulaciones por escenario')
    y -= 26
    pdf.setFont('Helvetica', 11)
    for kind, label in LAB_NAMES.items():
        pdf.drawString(48, y, f'{label}: {summary["counts"][kind]}')
        y -= 22
    y -= 24
    pdf.setFont('Helvetica-Bold', 15)
    pdf.drawString(42, y, 'Historial reciente (maximo 100)')
    y -= 21
    pdf.setFont('Helvetica', 9)
    pdf.setFillColor(HexColor('#33485b'))
    for i, e in enumerate(summary['history']):
        if y < 72:
            pdf.setFont('Helvetica', 8)
            pdf.drawRightString(w - 42, 34, f'Pagina {pdf.getPageNumber()}')
            pdf.showPage()
            y = h - 55
            pdf.setFillColor(HexColor('#33485b'))
            pdf.setFont('Helvetica', 9)
        pdf.drawString(45, y, e['time'] + '  |  ' + e['title'])
        y -= 15
    if not summary['history']:
        pdf.drawString(45, y, 'Todavia no hay simulaciones registradas.')
        y -= 20
    if y < 95:
        pdf.showPage()
        y = h - 55
    pdf.setFillColor(HexColor('#64748b'))
    pdf.setFont('Helvetica-Oblique', 9)
    pdf.drawString(42, y-24, 'Las simulaciones son educativas; no equivalen a ataques reales ni auditorias de seguridad.')
    pdf.setFont('Helvetica', 8)
    pdf.drawRightString(w - 42, 34, f'Pagina {pdf.getPageNumber()}')
    pdf.save()
    out.seek(0)
    response = send_file(out, mimetype='application/pdf', as_attachment=True, download_name='CyberDefense_Informe.pdf')
    response.headers['Cache-Control'] = 'no-store'
    return response






# Portal empresarial local: registro de ventas con controles de acceso.
@app.get('/empresa')
def empresa():
    return render_template('empresa.html')


PRODUCTOS = {
    'Licencia de software': 18000,
    'Soporte técnico': 8500,
    'Mantenimiento preventivo': 12000,
    'Auditoría básica': 25000,
}

@app.get('/empresa/panel')
def empresa_panel():
    if session.get('role') not in ('user', 'admin'):
        return redirect(url_for('home'))
    with db() as c:
        ventas = c.execute('SELECT * FROM ventas WHERE empleado=? ORDER BY id DESC LIMIT 12', (session['username'],)).fetchall()
        resumen = c.execute('SELECT COUNT(*) AS cantidad, COALESCE(SUM(total_centavos), 0) AS total FROM ventas WHERE empleado=?',(session['username'],)).fetchone()
    return render_template('empresa_panel.html', productos=PRODUCTOS, ventas=ventas, resumen=resumen)

@app.post('/empresa/ventas')
def registrar_venta():
    if session.get('role') != 'user':
        abort(403)
    producto = request.form.get('producto', '')
    try:
        cantidad = int(request.form.get('cantidad', '0'))
    except (ValueError, TypeError):
        cantidad = 0
    if producto not in PRODUCTOS or not 1 <= cantidad <= 100:
        flash('Revisa el producto y la cantidad (1 a 100).', 'warning')
        return redirect(url_for('empresa_panel'))
    precio = PRODUCTOS[producto]
    with db() as c:
        c.execute('INSERT INTO ventas(created,empleado,producto,cantidad,precio_centavos,total_centavos) VALUES(?,?,?,?,?,?)', (now(),session['username'],producto,cantidad,precio,precio*cantidad))
        event(c,session['username'],request.remote_addr or 'local','venta_registrada','Operación comercial registrada')
    flash('Venta guardada correctamente.', 'success')
    return redirect(url_for('empresa_panel'))

@app.get('/empresa/administracion')
def empresa_administracion():
    if 'username' not in session:
        flash('Acceso restringido: primero debes autenticarte.', 'warning')
        return redirect(url_for('home'))
    if session.get('role') != 'admin':
        if register_company_denial():
            return render_template('empresa_bloqueada.html', seconds=COMPANY_BLOCK_SECONDS), 403
        return render_template('acceso_denegado.html'), 403
    return render_template('empresa_admin.html')


@app.get('/admin/bloqueos')
@admin_only
def admin_bloqueos():
    with db() as c:
        rows = c.execute('SELECT identity, username, source, attempts, blocked_until FROM company_limits WHERE blocked_until > ? ORDER BY blocked_until DESC', (now(),)).fetchall()
    return render_template('bloqueos.html', blocks=[dict(r) | {'remaining': max(0, r['blocked_until']-now())} for r in rows])


@app.post('/admin/desbloquear')
@admin_only
def admin_desbloquear():
    identity = request.form.get('identity','')
    with db() as c:
        row = c.execute('SELECT username,source FROM company_limits WHERE identity=?', (identity,)).fetchone()
        if row:
            c.execute('DELETE FROM company_limits WHERE identity=?', (identity,))
            event(c, row['username'], row['source'], 'desbloqueado', 'NEXORA: desbloqueo manual por administrador')
            flash('Acceso restaurado.', 'success')
        else:
            flash('El bloqueo ya no existe.', 'warning')
    return redirect(url_for('admin_bloqueos'))


@app.post('/admin/limpiar-actividad')
@admin_only
def limpiar_actividad():
    # La proteccion CSRF global verifica este formulario.
    if request.form.get('confirmacion') != 'BORRAR':
        flash('Confirmación incorrecta. No se modificaron los datos.', 'warning')
        return redirect(url_for('dashboard'))
    # Copia verificable antes de vaciar actividad, preservando los usuarios.
    with db() as source:
        backup = DB.parent / ('respaldo_actividad_' + local_datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.db')
        with sqlite3.connect(backup) as target:
            source.backup(target)
        source.execute('DELETE FROM events')
        source.execute('DELETE FROM limits')
        source.execute('DELETE FROM company_limits')
    flash('Actividad reiniciada. Se conservaron usuarios y se creó un respaldo local.', 'success')
    return redirect(url_for('dashboard'))

@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Inicializar al importar el modulo: obligatorio para Gunicorn (app:app).
init_db()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
