from flask import Flask, render_template, request, jsonify, session, send_from_directory
import sqlite3
import os
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'desarrollo_web_seguro_2026'

# La base de datos se creará en la raíz del proyecto
DB_PATH = 'database.db'

# --- CONFIGURACIÓN DE ARCHIVOS ---
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Límite de 16MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- BASE DE DATOS ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # Tabla de Usuarios (con sistema de verificación)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    verification_token TEXT
                )''')
    # Tabla de Mensajes
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

# Inicializamos la BD al arrancar el servidor
with app.app_context():
    init_db()

# --- RUTAS PRINCIPALES ---
@app.route('/')
def index():
    # Recuerda: El archivo index.html DEBE estar dentro de una carpeta llamada "templates"
    return render_template('index.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/api/auth/status', methods=['GET'])
def status():
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'user_id': session['user_id'], 'name': session.get('user_name'), 'email': session.get('email')})
    return jsonify({'logged_in': False})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not name or not email or not password:
        return jsonify({'error': 'Todos los campos son obligatorios'}), 400
    
    # Generar código de 6 dígitos
    code = ''.join(random.choices(string.digits, k=6))
    
    # IMPORTANTE: Este print hace que el código aparezca en los Logs de Render
    print(f"==================================================")
    print(f"CÓDIGO DE VERIFICACIÓN PARA {email}: {code}")
    print(f"==================================================")
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password_hash, name, is_verified, verification_token) VALUES (?, ?, ?, 0, ?)", 
                  (email, generate_password_hash(password), name, code))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'needs_verification': True, 'email': email})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El correo ya está registrado'}), 400
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_code():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ? AND verification_token = ?", (email, code))
    user = c.fetchone()
    
    if user:
        c.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user['id'],))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
        
    conn.close()
    return jsonify({'error': 'Código inválido o correo incorrecto'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (data.get('email'),))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], data.get('password')):
        if user['is_verified'] == 0:
            return jsonify({'error': 'Cuenta pendiente de verificación', 'needs_verification': True, 'email': user['email']}), 403
        
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['email'] = user['email']
        return jsonify({'success': True})
        
    return jsonify({'error': 'Credenciales incorrectas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# --- RUTAS DE MENSAJERÍA ---
@app.route('/api/users/search', methods=['POST'])
def search_user():
    if 'user_id' not in session: 
        return jsonify({'error': 'No autorizado'}), 401
        
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, email FROM users WHERE email = ? AND id != ? AND is_verified = 1", (request.json.get('email'), session['user_id']))
    user = c.fetchone()
    conn.close()
    
    if user: 
        return jsonify(dict(user))
    return jsonify({'error': 'Usuario no encontrado o no verificado'}), 404

@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    if 'user_id' not in session: 
        return jsonify({'error': 'No autorizado'}), 401
        
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    query = '''
        SELECT u.id, u.name, u.email, 
               (SELECT content FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_message,
               (SELECT file_path FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_file,
               (SELECT timestamp FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id) ORDER BY timestamp DESC LIMIT 1) as last_timestamp
        FROM users u WHERE u.id IN (SELECT sender_id FROM messages WHERE receiver_id = ? UNION SELECT receiver_id FROM messages WHERE sender_id = ?)
        ORDER BY last_timestamp DESC
    '''
    c.execute(query, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    convs = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(convs)

@app.route('/api/messages/<int:other_user_id>', methods=['GET'])
def get_messages(other_user_id):
    if 'user_id' not in session: 
        return jsonify({'error': 'No autorizado'}), 401
        
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT m.*, strftime('%H:%M', m.timestamp, 'localtime') as time_fmt 
        FROM messages m WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (session['user_id'], other_user_id, other_user_id, session['user_id']))
    messages = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(messages)

@app.route('/api/messages/send', methods=['POST'])
def send_message():
    if 'user_id' not in session: 
        return jsonify({'error': 'No autorizado'}), 401
        
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content', '')
    file = request.files.get('attachment')
    filename = None
    
    if not receiver_id: 
        return jsonify({'error': 'Destinatario inválido'}), 400
    if not content and not file: 
        return jsonify({'error': 'Mensaje vacío'}), 400
    
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, content, file_path) VALUES (?, ?, ?, ?)", (session['user_id'], receiver_id, content, filename))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
