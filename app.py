from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask import flash
import bcrypt
import os
import time
from werkzeug.utils import secure_filename
from functools import wraps
from flask import get_flashed_messages
import re  # Para validação de e-mail e telefone
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-key-not-secure'

# Configurações para upload de imagens
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}




# Configuração do MongoDB - substitua esta parte
app.config['MONGO_URI'] = os.environ.get('MONGO_URI') or 'mongodb+srv://juliocardoso:ttAJxnWdq6VteFCD@cluster0.fynj6mg.mongodb.net/chefabook?retryWrites=true&w=majority&appName=Cluster0'
client = MongoClient(app.config['MONGO_URI'])
db = client.get_database('chefabook')  # Especifica o nome do banco de dados
fs = GridFS(db)  # Para armazenamento de arquivos (imagens)




# Coleções
usuarios_col = db['usuarios']
receitas_col = db['receitas']

# Função para verificar extensão do arquivo
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Decorator para rotas que requerem login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator para rotas que requerem privilégios de admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('user_admin'):
            flash("Acesso restrito a administradores.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Credenciais do Administrador
ADMIN_CREDENTIALS = {
    "email": "admin@email.com",
    "password": "senha123"
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip().lower()
            telefone = request.form.get('telefone', '').strip()
            senha = request.form.get('senha', '').strip()
            confirmar_senha = request.form.get('confirmar_senha', '').strip()

            # Validações (mesmas do código original)
            if not nome:
                flash("O nome é obrigatório", "error")
                return render_template('cadastrar_usuario.html')

            if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                flash("Por favor, insira um e-mail válido.", "error")
                return render_template('cadastrar_usuario.html')

            telefone_limpo = re.sub(r'\D', '', telefone)
            if len(telefone_limpo) < 10 or len(telefone_limpo) > 11:
                flash("Telefone inválido. Insira DDD + número (10 ou 11 dígitos).", "error")
                return render_template('cadastrar_usuario.html')

            if len(senha) < 6:
                flash("A senha deve ter pelo menos 6 caracteres", "error")
                return render_template('cadastrar_usuario.html')

            if senha != confirmar_senha:
                flash("As senhas não coincidem. Digite novamente.", "error")
                return render_template('cadastrar_usuario.html')

            # Verificar se o e-mail já existe
            if usuarios_col.find_one({'email': email}):
                flash("Este e-mail já está cadastrado. Use outro ou faça login.", "error")
                return render_template('cadastrar_usuario.html')

            # Hash da senha
            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

            # Inserir usuário no MongoDB
            usuario = {
                'nome': nome,
                'email': email,
                'telefone': telefone_limpo,
                'senha': hashed_senha,
                'admin': False
            }
            usuarios_col.insert_one(usuario)

            flash("Cadastro realizado com sucesso! Faça login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Erro no cadastro: {str(e)}", "error")
            return render_template('cadastrar_usuario.html')

    return render_template('cadastrar_usuario.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '').strip()

        if not email or '@' not in email:
            flash("Por favor, insira um e-mail válido", "error")
            return render_template('login.html')
        
        if not senha:
            flash("Por favor, insira sua senha", "error")
            return render_template('login.html')

        try:
            usuario = usuarios_col.find_one({'email': email})
            
            if not usuario:
                flash("E-mail não encontrado. Verifique ou cadastre-se.", "error")
            else:
                if bcrypt.checkpw(senha.encode('utf-8'), usuario['senha']):
                    session['user_id'] = str(usuario['_id'])
                    session['user_nome'] = usuario['nome']
                    session['user_admin'] = usuario.get('admin', False)
                    flash("Login realizado com sucesso!", "success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("Senha incorreta. Tente novamente.", "error")
                
        except Exception as e:
            flash(f"Erro no login: {str(e)}", "error")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/cadastrar_receita', methods=['GET', 'POST'])
@login_required
def cadastrar_receita():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        categoria = request.form.get('categoria', '').strip()
        ingredientes = request.form.get('ingredientes', '').strip()
        preparo = request.form.get('preparo', '').strip()
        user_id = session['user_id']
        
        if 'imagem' not in request.files:
            flash("Nenhuma imagem enviada", "error")
            return redirect(request.url)
        
        file = request.files['imagem']
        
        if file.filename == '':
            flash("Nenhuma imagem selecionada", "error")
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                # Salva a imagem no GridFS
                imagem_id = fs.put(file, filename=secure_filename(file.filename))
                
                # Cria a receita no MongoDB
                receita = {
                    'titulo': titulo,
                    'categoria': categoria,
                    'ingredientes': ingredientes,
                    'preparo': preparo,
                    'imagem_id': imagem_id,
                    'user_id': user_id
                }
                receitas_col.insert_one(receita)
                
                flash("Receita cadastrada com sucesso!", "success")
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f"Erro ao cadastrar receita: {str(e)}", "error")
        else:
            flash("Tipo de arquivo não permitido", "error")

    return render_template('cadastrar_receitas.html')

@app.route('/visualizar_receitas')
@login_required
def visualizar_receitas():
    try:
        receitas = []
        for receita in receitas_col.find({'user_id': session['user_id']}):
            receitas.append({
                'id': str(receita['_id']),
                'titulo': receita['titulo'],
                'categoria': receita['categoria'],
                'ingredientes': receita['ingredientes'],
                'preparo': receita['preparo'],
                'user_id': receita['user_id'],
                'tem_imagem': 'imagem_id' in receita
            })

        return render_template('visualizar_receitas.html', receitas=receitas)
        
    except Exception as e:
        flash(f"Erro ao carregar receitas: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/imagem_receita/<receita_id>')
@login_required
def imagem_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if receita and 'imagem_id' in receita:
            imagem = fs.get(receita['imagem_id'])
            response = make_response(imagem.read())
            response.headers.set('Content-Type', 'image/jpeg')
            return response
        
    except Exception as e:
        print(f"Erro ao carregar imagem: {str(e)}")
    
    # Retorna uma imagem padrão se não encontrar
    from flask import send_from_directory
    return send_from_directory(app.static_folder, 'images/sem-imagem.jpg')

@app.route('/editar_receita/<receita_id>', methods=['GET', 'POST'])
@login_required
def editar_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para editá-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            categoria = request.form.get('categoria', '').strip()
            ingredientes = request.form.get('ingredientes', '').strip()
            preparo = request.form.get('preparo', '').strip()
            
            update_data = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo
            }
            
            if 'imagem' in request.files:
                file = request.files['imagem']
                if file and file.filename != '' and allowed_file(file.filename):
                    # Remove a imagem antiga se existir
                    if 'imagem_id' in receita:
                        fs.delete(receita['imagem_id'])
                    # Adiciona a nova imagem
                    update_data['imagem_id'] = fs.put(file, filename=secure_filename(file.filename))

            receitas_col.update_one(
                {'_id': ObjectId(receita_id)},
                {'$set': update_data}
            )
            
            flash("Receita atualizada com sucesso!", "success")
            return redirect(url_for('visualizar_receitas'))
        
        return render_template('editar_receita.html', receita=receita)
        
    except Exception as e:
        flash(f"Erro ao editar receita: {e}", "error")
        return redirect(url_for('visualizar_receitas'))

@app.route('/excluir_receita/<receita_id>', methods=['POST'])
@login_required
def excluir_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para excluí-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        # Remove a imagem se existir
        if 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso!", "success")
        
    except Exception as e:
        flash(f"Erro ao excluir receita: {e}", "error")
    
    return redirect(url_for('visualizar_receitas'))

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            session['user_id'] = "admin"  # ID especial para admin
            session['user_admin'] = True
            session['user_nome'] = "Administrador"
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))
        
        flash("Credenciais inválidas!", "error")
        return redirect(url_for("login_admin"))

    return render_template("login_admin.html")

@app.route("/painel_admin")
@admin_required
def painel_admin():
    usuarios = list(usuarios_col.find({}, {'nome': 1, 'email': 1, 'telefone': 1}))
    receitas = list(receitas_col.find())
    return render_template("painel_admin.html", usuarios=usuarios, receitas=receitas)

@app.route("/excluir_usuario/<usuario_id>", methods=["POST"])
@admin_required
def excluir_usuario(usuario_id):
    try:
        # Primeiro exclui as receitas do usuário
        receitas_col.delete_many({'user_id': usuario_id})
        # Depois exclui o usuário
        usuarios_col.delete_one({'_id': ObjectId(usuario_id)})
        flash("Usuário e suas receitas excluídos com sucesso.", "success")
    except Exception as e:
        flash(f"Erro ao excluir usuário: {e}", "error")
    
    return redirect(url_for("painel_admin"))

@app.route("/excluir_receita_admin/<receita_id>", methods=["POST"])
@admin_required
def excluir_receita_admin(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id)})
        if receita and 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso.", "success")
    except Exception as e:
        flash(f"Erro ao excluir receita: {e}", "error")
    
    return redirect(url_for("painel_admin"))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    app.run(debug=True)