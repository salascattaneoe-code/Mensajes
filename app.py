from flask import Flask, render_template, request, jsonify, session, send_from_directory
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'super_secret_saas_key_prod'
DB_NAME = 'database.db'

# Configuración de subida de archivos
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Limitamos el tamaño máximo a 16MB para proteger el servidor
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Asegurar que la carpeta de subidas exista
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    file_path TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

@app.route('/')
def index():
    return render_template('index.html')

# --- RUTA PARA DESCARGAR/VER ARCHIVOS ---
@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API DE AUTENTICACIÓN ---
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'user_id': session['user_id'], 'name': session.get('user_name'), 'email': session.get('email')})
    return jsonify({'logged_in': False})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name, email, password = data.get('name'), data.get('email'), data.get('password')
    if not name or not email or not password: return jsonify({'error': 'Campos obligatorios faltantes'}), 400
    try:
        conn = get_db(); c = conn.cursor()
        c.execute("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)", (email, generate_password_hash(password), name))
        conn.commit(); conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError: return jsonify({'error': 'El correo ya existe'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (data.get('email'),))
    user = c.fetchone(); conn.close()
    if user and check_password_hash(user['password_hash'], data.get('password')):
        session['user_id'], session['user_name'], session['email'] = user['id'], user['name'], user['email']
        return jsonify({'success': True})
    return jsonify({'error': 'Credenciales inválidas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# --- API DE MENSAJERÍA ---
@app.route('/api/users/search', methods=['POST'])
def search_user():
    if 'user_id' not in session: return jsonify({'error': 'No autorizado'}), 401
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, name, email FROM users WHERE email = ? AND id != ?", (request.json.get('email'), session['user_id']))
    user = c.fetchone(); conn.close()
    if user: return jsonify(dict(user))
    return jsonify({'error': 'Usuario no encontrado'}), 404

@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    if 'user_id' not in session: return jsonify({'error': 'No autorizado'}), 401
    user_id = session['user_id']
    conn = get_db(); c = conn.cursor()
    query = '''
        SELECT u.id, u.name, u.email, 
               (SELECT content FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_message,
               (SELECT file_path FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_file,
               (SELECT timestamp FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_timestamp
        FROM users u WHERE u.id IN (SELECT sender_id FROM messages WHERE receiver_id = ? UNION SELECT receiver_id FROM messages WHERE sender_id = ?)
        ORDER BY last_timestamp DESC
    '''
    c.execute(query, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    
    convs = []
    for row in c.fetchall():
        d = dict(row)
        # Convertimos la hora del último mensaje a zona horaria de Argentina (UTC-3)
        if d.get('last_timestamp'):
            try:
                dt = datetime.strptime(d['last_timestamp'], '%Y-%m-%d %H:%M:%S')
                dt_arg = dt - timedelta(hours=3)
                d['last_timestamp'] = dt_arg.strftime('%H:%M')
            except Exception:
                pass
        convs.append(d)
        
    conn.close()
    return jsonify(convs)

@app.route('/api/messages/<int:other_user_id>', methods=['GET'])
def get_messages(other_user_id):
    if 'user_id' not in session: return jsonify({'error': 'No autorizado'}), 401
    conn = get_db(); c = conn.cursor()
    c.execute('''
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (session['user_id'], other_user_id, other_user_id, session['user_id']))
    
    messages = []
    for row in c.fetchall():
        d = dict(row)
        # Convertimos el timestamp UTC a la hora formateada de Argentina (UTC-3)
        if d.get('timestamp'):
            try:
                dt = datetime.strptime(d['timestamp'], '%Y-%m-%d %H:%M:%S')
                dt_arg = dt - timedelta(hours=3)
                d['time_fmt'] = dt_arg.strftime('%H:%M')
            except Exception:
                d['time_fmt'] = d['timestamp']
        else:
            d['time_fmt'] = ""
        messages.append(d)
        
    conn.close()
    return jsonify(messages)

# --- RUTA DE ENVÍO QUE SOPORTA ARCHIVOS (FORM-DATA) ---
@app.route('/api/messages/send', methods=['POST'])
def send_message():
    if 'user_id' not in session: return jsonify({'error': 'No autorizado'}), 401
    
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content', '')
    file = request.files.get('attachment')
    filename = None

    if not receiver_id: return jsonify({'error': 'Destinatario inválido'}), 400
    if not content and not file: return jsonify({'error': 'El mensaje no puede estar vacío'}), 400

    # Procesar archivo si viene alguno adjunto
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, content, file_path) VALUES (?, ?, ?, ?)", 
              (session['user_id'], receiver_id, content, filename))
    conn.commit(); conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
