from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import secrets
import string
import os
import bcrypt
import random
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

#Config cookie segura
app.config['ENV'] = 'production'
app.config['SESSION_COOKIE_SECURE'] = (app.config['ENV'] == 'production')

# Función para crear las tablas users y passwords si no existen
def create_table():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT, login_attempts INTEGER, blocked INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens
                 (token TEXT PRIMARY KEY, user_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, app_name TEXT, username TEXT, password TEXT, details TEXT)''')
    conn.commit()
    conn.close()

# Llamamos a la función create_table para asegurarnos de que la tabla exista
create_table()

# Generar un token de autenticación único
def generate_auth_token():
    return secrets.token_urlsafe(16)

def get_user_by_username(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_token(token):
    print("Token:", token)  # Registro de depuración
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT user_id FROM tokens WHERE token = ?", (token,))
    token_data = c.fetchone()
    if token_data:
        user_id = token_data[0]  # Suponiendo que el ID de usuario esté en la primera columna de la tabla tokens
        print("User ID:", user_id)  # Registro de depuración
        c.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user = c.fetchone()
    else:
        user = None
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user

# Función para crear una cuenta de administrador
def create_admin_account():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(b'admin', bcrypt.gensalt()).decode('utf-8')
    c.execute("INSERT INTO users (username, password, role, login_attempts, blocked) VALUES (?, ?, ?, ?, ?)", ('admin', hashed_password, 'admin', 0, 0))
    conn.commit()
    conn.close()


# Llamamos a la función create_admin_account para crear la cuenta de administrador si no existe
create_admin_account()

# Configuración de la ruta de inicio
@app.route('/')
def index():
    return render_template('login.html')

# Ruta del registro
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        
        # Verificar si ya existe un usuario con el mismo nombre de usuario
        existing_user = get_user_by_username(username)
        if existing_user:
            error_message = "Ya existe un usuario con este nombre. Por favor, elige otro nombre de usuario."
            return render_template('signup.html', form=form, error_message=error_message)
        
        # Hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Guardar la información en la base de datos
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password.decode('utf-8'), 'user'))  # Asignar el rol 'user' al nuevo usuario
        conn.commit()
        conn.close()
        
        # Redirigir al login después de registrarse
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Ruta del login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = get_user_by_username(username)
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            if user[5] == 1: # Verificar si el usuario está bloqueado
                error_message = "Usuario bloqueado. Por favor, contacta al administrador."
                return render_template('login.html', form=form, error_message=error_message)
            
            # Las credenciales son válidas, resetear el contador de intentos fallidos
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("UPDATE users SET login_attempts = 0 WHERE user_id = ?", (user[0],))
            conn.commit()
            conn.close()
            
            # Generar un token de autenticación y almacenarlo en la base de datos
            token = generate_auth_token()
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO tokens (token, user_id) VALUES (?, ?)", (token, user[0]))
            conn.commit()
            conn.close()
            # Almacena el token en la sesión del usuario
            session['user_id'] = token
            # Redirigir al dashboard o al admin panel según el rol del usuario
            if user[3] == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('dashboard', token=token))
        else:
            # Las credenciales son inválidas, incrementar el contador de intentos fallidos
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?", (username,))
            conn.commit()
            
            # Verificar si se ha alcanzado el límite de intentos fallidos (en este caso 5)
            if user and user[4] >= 5: # user[4] es el número de intentos fallidos
                # Bloquear la cuenta
                c.execute("UPDATE users SET blocked = 1 WHERE username = ?", (username,))
                conn.commit()
                conn.close()
                error_message = "Has excedido el número máximo de intentos fallidos. Tu cuenta ha sido bloqueada. Por favor, contacta al administrador."
            else:
                error_message = "Usuario o contraseña incorrectos. Por favor, inténtalo de nuevo."
            conn.close()
            return render_template('login.html', form=form, error_message=error_message)
    return render_template('login.html', form=form)

# Ruta del dashboard
@app.route('/dashboard')
def dashboard():
    token = session.get('user_id')  # Obtener el token de la sesión del usuario
    print("Token from session:", token)  # Registro de depuración
    if not token:
        return redirect(url_for('login'))
    user = get_user_by_token(token)
    print("User:", user)  # Registro de depuración
    if not user:
        return redirect(url_for('login'))
    user_id = user[0]  # Obtener el ID de usuario
    print("User ID:", user_id)  # Registro de depuración
    
    form = LoginForm()  # Instanciar el formulario
    
    # Obtener el nombre de usuario del ID de usuario
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    username = c.fetchone()[0]
    
    # Obtener las contraseñas del usuario
    c.execute("SELECT * FROM passwords WHERE user_id = ?", (user_id,))
    passwords = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', username=username, passwords=passwords, form=form)  # Pasar el formulario a la plantilla

#Ruta del panel admin
@app.route('/admin_panel')
def admin_panel():
    form = LoginForm()
    # Verificar si el usuario tiene permiso de administrador
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_token(session['user_id'])
    if not user or user[3] != 'admin':
        return redirect(url_for('login'))
    
    # Obtener la lista de usuarios registrados (excluyendo al administrador)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE role != 'admin'")
    users = c.fetchall()
    print("Usuarios recuperados:", users)  # Imprimir los usuarios recuperados para verificar
    
    conn.close()
    
    return render_template('admin_panel.html', users=users, form=form)  # Pasar el formulario a la plantilla


@app.route('/block_user/<int:user_id>')
def block_user(user_id):
    # Verificar si el usuario tiene permiso de administrador
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_token = session['user_id']
    admin_user = get_user_by_token(admin_token)
    if not admin_user or admin_user[3] != 'admin':
        return redirect(url_for('login'))
    
    # Verificar si el usuario existe en la base de datos
    existing_user = get_user_by_token(admin_token)
    if not existing_user:
        flash('El usuario no existe.')
        return redirect(url_for('admin_panel'))
    
    # Actualizar el estado de bloqueo del usuario
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE users SET blocked = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_panel'))

@app.route('/unblock_user/<int:user_id>')
def unblock_user(user_id):
    # Verificar si el usuario tiene permiso de administrador
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_token = session['user_id']
    admin_user = get_user_by_token(admin_token)
    if not admin_user or admin_user[3] != 'admin':
        return redirect(url_for('login'))
    
    # Verificar si el usuario existe en la base de datos
    existing_user = get_user_by_token(admin_token)
    if not existing_user:
        flash('El usuario no existe.')
        return redirect(url_for('admin_panel'))
    
    # Actualizar el estado de bloqueo del usuario
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE users SET blocked = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_panel'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    print("Formulario recibido:", request.form)  # Imprimir el contenido del formulario
    print("User ID recibido:", user_id)  # Imprimir el ID de usuario recibido
    print("Se accedió a la ruta de eliminar usuario.")
    # Verificar si el usuario tiene permiso de administrador
    if 'user_id' not in session:
        return redirect(url_for('login'))
    admin_token = session['user_id']
    admin_user = get_user_by_token(admin_token)
    if not admin_user or admin_user[3] != 'admin':
        return redirect(url_for('login'))
    
    # Verificar si el usuario que se desea eliminar existe en la base de datos
    existing_user = get_user_by_id(user_id)
    if not existing_user:
        flash('El usuario no existe.')
        return redirect(url_for('admin_panel'))
    
    # Eliminar el usuario de la base de datos
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_panel'))


def generate_random_password():
    # Definir los caracteres que se utilizarán para generar la contraseña
    characters = string.ascii_letters + string.digits + string.punctuation
    # Definir la longitud de la contraseña entre 18 y 22 caracteres
    password_length = random.randint(18, 22)
    # Generar la contraseña aleatoria
    password = ''.join(random.choices(characters, k=password_length))
    return password

#Ruta para add password
@app.route('/add_password', methods=['POST'])
def add_password():
    if request.method == 'POST':
        app_name = request.form['app_name']
        username = request.form['username']
        details = request.form['details']
        
        # Generar una contraseña segura aleatoria
        password = generate_random_password()
        
        # Obtener el token de autenticación de la sesión del usuario
        token = session.get('user_id')
        if not token:
            return redirect(url_for('login'))
        
        # Obtener el ID de usuario a partir del token de autenticación
        user = get_user_by_token(token)
        if not user:
            return redirect(url_for('login'))
        user_id = user[0]  # Obtener el ID de usuario
        
        # Guardar la información en la base de datos
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO passwords (user_id, app_name, username, password, details) VALUES (?, ?, ?, ?, ?)", (user_id, app_name, username, password, details))
        conn.commit()
        conn.close()
        
        # Redirigir al dashboard después de agregar la contraseña
        return redirect(url_for('dashboard'))

    # Redirigir al dashboard aunque no se haya enviado el formulario
    return redirect(url_for('dashboard')) 


# Ruta para editar una contraseña
@app.route('/edit_password/<int:password_id>', methods=['POST'])
def edit_password(password_id):
    if request.method == 'POST':
        app_name = request.form['app_name']
        username = request.form['username']
        details = request.form['details']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE passwords SET app_name = ?, username = ?, details = ? WHERE id = ?", (app_name, username, details, password_id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('dashboard'))

# Ruta para borrar una contraseña
@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# Ruta para cerrar sesión
@app.route('/logout', methods=['POST'])
def logout():
    # Eliminar la sesión del usuario
    session.pop('user_id', None)
    # Redirigir al usuario al login
    return redirect(url_for('login'))

# Otras rutas y lógica de la aplicación...

if __name__ == '__main__':
    app.run(debug=True)
