from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)  # Permitir requisições de qualquer origem

# Configuração do banco de dados SQLite
DATABASE = 'inksa_auth.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializar o banco de dados com as tabelas necessárias"""
    conn = get_db_connection()
    
    # Tabela de usuários
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_type TEXT NOT NULL,  -- 'admin', 'restaurant', 'delivery', 'client'
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Tabela de tokens de recuperação de senha
    conn.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Inserir usuários de teste se não existirem
    users_test = [
        ('admin@inksa.com', 'admin123', 'admin', 'Administrador Inksa'),
        ('restaurante@inksa.com', 'rest123', 'restaurant', 'Restaurante Teste'),
        ('entregador@inksa.com', 'ent123', 'delivery', 'Entregador Teste'),
        ('cliente@inksa.com', 'cli123', 'client', 'Cliente Teste')
    ]
    
    for email, password, user_type, name in users_test:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            conn.execute(
                'INSERT INTO users (email, password_hash, user_type, name) VALUES (?, ?, ?, ?)',
                (email, password_hash, user_type, name)
            )
        except sqlite3.IntegrityError:
            # Usuário já existe
            pass
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Gerar hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token():
    """Gerar token seguro para recuperação de senha"""
    return secrets.token_urlsafe(32)

def send_reset_email(email, token, user_name):
    """Simular envio de email de recuperação de senha"""
    # Em produção, aqui seria configurado um serviço de email real
    reset_link = f"http://localhost:5000/reset-password?token={token}"
    
    print(f"""
    ==========================================
    EMAIL DE RECUPERAÇÃO DE SENHA SIMULADO
    ==========================================
    Para: {email}
    Nome: {user_name}
    
    Olá {user_name},
    
    Você solicitou a recuperação de sua senha no Inksa.
    
    Clique no link abaixo para redefinir sua senha:
    {reset_link}
    
    Este link expira em 1 hora.
    
    Se você não solicitou esta recuperação, ignore este email.
    
    Atenciosamente,
    Equipe Inksa
    ==========================================
    """)
    
    return True

@app.route('/api/login', methods=['POST'])
def login():
    """Endpoint de login"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user_type = data.get('user_type', 'client')  # Tipo padrão: cliente
        
        if not email or not password:
            return jsonify({'error': 'Email e senha são obrigatórios'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND user_type = ? AND is_active = 1',
            (email, user_type)
        ).fetchone()
        conn.close()
        
        if user and user['password_hash'] == hash_password(password):
            return jsonify({
                'success': True,
                'message': 'Login realizado com sucesso',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'user_type': user['user_type']
                }
            })
        else:
            return jsonify({'error': 'Credenciais inválidas'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Endpoint para solicitar recuperação de senha"""
    try:
        data = request.get_json()
        email = data.get('email')
        user_type = data.get('user_type', 'client')
        
        if not email:
            return jsonify({'error': 'Email é obrigatório'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND user_type = ? AND is_active = 1',
            (email, user_type)
        ).fetchone()
        
        if not user:
            # Por segurança, sempre retornar sucesso mesmo se o usuário não existir
            return jsonify({
                'success': True,
                'message': 'Se o email estiver cadastrado, você receberá as instruções de recuperação'
            })
        
        # Gerar token de recuperação
        token = generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=1)  # Token expira em 1 hora
        
        conn.execute(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user['id'], token, expires_at)
        )
        conn.commit()
        conn.close()
        
        # Enviar email (simulado)
        send_reset_email(email, token, user['name'])
        
        return jsonify({
            'success': True,
            'message': 'Se o email estiver cadastrado, você receberá as instruções de recuperação',
            'token': token  # Em produção, remover esta linha (apenas para teste)
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Endpoint para redefinir senha com token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({'error': 'Token e nova senha são obrigatórios'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'A senha deve ter pelo menos 6 caracteres'}), 400
        
        conn = get_db_connection()
        
        # Verificar se o token é válido e não expirou
        reset_token = conn.execute('''
            SELECT rt.*, u.email, u.name 
            FROM password_reset_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.token = ? AND rt.used = 0 AND rt.expires_at > ?
        ''', (token, datetime.now())).fetchone()
        
        if not reset_token:
            conn.close()
            return jsonify({'error': 'Token inválido ou expirado'}), 400
        
        # Atualizar a senha do usuário
        new_password_hash = hash_password(new_password)
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, reset_token['user_id'])
        )
        
        # Marcar o token como usado
        conn.execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = ?',
            (reset_token['id'],)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Senha redefinida com sucesso'
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Endpoint para validar token de recuperação"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token é obrigatório'}), 400
        
        conn = get_db_connection()
        reset_token = conn.execute('''
            SELECT rt.*, u.email, u.name 
            FROM password_reset_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.token = ? AND rt.used = 0 AND rt.expires_at > ?
        ''', (token, datetime.now())).fetchone()
        conn.close()
        
        if reset_token:
            return jsonify({
                'valid': True,
                'email': reset_token['email'],
                'name': reset_token['name']
            })
        else:
            return jsonify({'valid': False})
            
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    """Endpoint para alterar senha (usuário logado)"""
    try:
        data = request.get_json()
        email = data.get('email')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        user_type = data.get('user_type', 'client')
        
        if not email or not current_password or not new_password:
            return jsonify({'error': 'Todos os campos são obrigatórios'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'A nova senha deve ter pelo menos 6 caracteres'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND user_type = ? AND is_active = 1',
            (email, user_type)
        ).fetchone()
        
        if not user or user['password_hash'] != hash_password(current_password):
            conn.close()
            return jsonify({'error': 'Senha atual incorreta'}), 401
        
        # Atualizar a senha
        new_password_hash = hash_password(new_password)
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, user['id'])
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Senha alterada com sucesso'
        })
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Endpoint para listar usuários (apenas para admin)"""
    try:
        conn = get_db_connection()
        users = conn.execute(
            'SELECT id, email, name, user_type, created_at, is_active FROM users ORDER BY created_at DESC'
        ).fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'user_type': user['user_type'],
                'created_at': user['created_at'],
                'is_active': bool(user['is_active'])
            })
        
        return jsonify({'users': users_list})
        
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    """Página HTML para redefinir senha"""
    token = request.args.get('token')
    
    html = f'''
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redefinir Senha - Inksa</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #ff6b35, #f7931e);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                max-width: 400px;
                width: 100%;
            }}
            .logo {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .logo h1 {{
                color: #ff6b35;
                margin: 0;
                font-size: 2.5em;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #333;
            }}
            input {{
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                box-sizing: border-box;
            }}
            input:focus {{
                border-color: #ff6b35;
                outline: none;
            }}
            button {{
                width: 100%;
                padding: 12px;
                background: #ff6b35;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: background 0.3s;
            }}
            button:hover {{
                background: #e55a2b;
            }}
            button:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
            .message {{
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
                text-align: center;
            }}
            .success {{
                background: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }}
            .error {{
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }}
            .loading {{
                background: #d1ecf1;
                color: #0c5460;
                border: 1px solid #bee5eb;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>Inksa</h1>
                <p>Redefinir Senha</p>
            </div>
            
            <div id="message"></div>
            
            <form id="resetForm">
                <div class="form-group">
                    <label for="newPassword">Nova Senha:</label>
                    <input type="password" id="newPassword" required minlength="6" 
                           placeholder="Digite sua nova senha (mín. 6 caracteres)">
                </div>
                
                <div class="form-group">
                    <label for="confirmPassword">Confirmar Senha:</label>
                    <input type="password" id="confirmPassword" required minlength="6" 
                           placeholder="Confirme sua nova senha">
                </div>
                
                <button type="submit" id="submitBtn">Redefinir Senha</button>
            </form>
        </div>

        <script>
            const token = '{token}';
            const messageDiv = document.getElementById('message');
            const form = document.getElementById('resetForm');
            const submitBtn = document.getElementById('submitBtn');

            function showMessage(text, type) {{
                messageDiv.innerHTML = `<div class="message ${{type}}">${{text}}</div>`;
            }}

            // Validar token ao carregar a página
            if (!token) {{
                showMessage('Token de recuperação não fornecido.', 'error');
                form.style.display = 'none';
            }} else {{
                // Validar token
                fetch('/api/validate-token', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{ token: token }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (!data.valid) {{
                        showMessage('Token inválido ou expirado. Solicite uma nova recuperação de senha.', 'error');
                        form.style.display = 'none';
                    }} else {{
                        showMessage(`Olá ${{data.name}}, defina sua nova senha abaixo.`, 'loading');
                    }}
                }})
                .catch(error => {{
                    showMessage('Erro ao validar token. Tente novamente.', 'error');
                    form.style.display = 'none';
                }});
            }}

            form.addEventListener('submit', function(e) {{
                e.preventDefault();
                
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                
                if (newPassword !== confirmPassword) {{
                    showMessage('As senhas não coincidem.', 'error');
                    return;
                }}
                
                if (newPassword.length < 6) {{
                    showMessage('A senha deve ter pelo menos 6 caracteres.', 'error');
                    return;
                }}
                
                submitBtn.disabled = true;
                submitBtn.textContent = 'Redefinindo...';
                showMessage('Redefinindo senha...', 'loading');
                
                fetch('/api/reset-password', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        token: token,
                        new_password: newPassword
                    }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        showMessage('Senha redefinida com sucesso! Você já pode fazer login com sua nova senha.', 'success');
                        form.style.display = 'none';
                    }} else {{
                        showMessage(data.error || 'Erro ao redefinir senha.', 'error');
                        submitBtn.disabled = false;
                        submitBtn.textContent = 'Redefinir Senha';
                    }}
                }})
                .catch(error => {{
                    showMessage('Erro ao redefinir senha. Tente novamente.', 'error');
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Redefinir Senha';
                }});
            }});
        </script>
    </body>
    </html>
    '''
    
    return html

@app.route('/', methods=['GET'])
def index():
    """Página inicial da API"""
    return jsonify({
        'message': 'Inksa Authentication API',
        'version': '1.0.0',
        'endpoints': {
            'POST /api/login': 'Fazer login',
            'POST /api/forgot-password': 'Solicitar recuperação de senha',
            'POST /api/reset-password': 'Redefinir senha com token',
            'POST /api/validate-token': 'Validar token de recuperação',
            'POST /api/change-password': 'Alterar senha (usuário logado)',
            'GET /api/users': 'Listar usuários',
            'GET /reset-password?token=': 'Página para redefinir senha'
        }
    })

if __name__ == '__main__':
    # Inicializar banco de dados
    init_db()
    print("Banco de dados inicializado com sucesso!")
    print("Usuários de teste criados:")
    print("- admin@inksa.com / admin123 (Administrador)")
    print("- restaurante@inksa.com / rest123 (Restaurante)")
    print("- entregador@inksa.com / ent123 (Entregador)")
    print("- cliente@inksa.com / cli123 (Cliente)")
    print()
    
    # Configuração de porta para Railway
    port = int(os.environ.get('PORT', 5000))
    print(f"API rodando na porta: {port}")
    
    # Executar aplicação
    app.run(host='0.0.0.0', port=port, debug=False)

