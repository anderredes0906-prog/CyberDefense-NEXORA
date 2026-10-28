from pathlib import Path
from getpass import getpass
import sqlite3
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash

root = Path(__file__).resolve().parent
db_path = root / 'cyberdefense.db'
if not db_path.is_file():
    raise SystemExit('No se encontro cyberdefense.db. Pon este script en la carpeta CyberDefense, junto a app.py.')
with sqlite3.connect(db_path) as conn:
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", ('admin',)).fetchone()
if not exists:
    raise SystemExit('No se encontro el usuario admin en esta base de datos.')
password = getpass('Nueva contrasena de admin (12 caracteres minimo): ')
confirmation = getpass('Repite la nueva contrasena: ')
if len(password) < 12 or password != confirmation:
    raise SystemExit('Las contrasenas no coinciden o tienen menos de 12 caracteres. No se modifico nada.')
backup_path = root / ('cyberdefense_backup_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.db')
with sqlite3.connect(db_path) as conn, sqlite3.connect(backup_path) as dst:
    conn.backup(dst)
with sqlite3.connect(db_path) as conn:
    conn.execute('UPDATE users SET password_hash = ? WHERE username = ?', (generate_password_hash(password), 'admin'))
print('Contrasena de admin actualizada correctamente.')
print('Copia de seguridad creada:', backup_path.name)
print('Reinicia CyberDefense e inicia sesion con la nueva contrasena.')
