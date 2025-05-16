# Importações de bibliotecas necessárias para os testes
import unittest
from flask import get_flashed_messages
from flask.testing import FlaskClient
import sqlite3
import io
import bcrypt
import os
from app import app, criar_tabelas, conectar_db, ADMIN_CREDENTIALS

# Classe principal de testes para usuários
class TestUsuario(unittest.TestCase):
    
    # ==================================================
    # CONFIGURAÇÃO INICIAL DO AMBIENTE DE TESTES
    # ==================================================
    
    @classmethod
    def setUpClass(cls):
        """Configuração inicial para todos os testes"""
        # Configura a aplicação para modo de teste
        app.config['TESTING'] = True  # Desativa erros durante os testes
        app.config['WTF_CSRF_ENABLED'] = False  # Desativa CSRF para testes de formulário
        app.config['SERVER_NAME'] = 'localhost'  # Define um nome de servidor para testes
        
        cls.app = app
        cls.client = app.test_client()  # Cria um cliente de teste
        
        # Cria as tabelas no banco de dados antes de qualquer teste
        with app.app_context():
            criar_tabelas()
    
    @classmethod
    def tearDownClass(cls):
        """Limpeza após todos os testes"""
        with app.app_context():
            cls.limpar_tabelas()  # Limpa o banco de dados após todos os testes
    
    # ==================================================
    # MÉTODOS AUXILIARES PARA OS TESTES
    # ==================================================
    
    @staticmethod
    def limpar_tabelas():
        """Remove todos os registros das tabelas"""
        with conectar_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM usuarios")  # Limpa tabela de usuários
            cursor.execute("DELETE FROM receitas")  # Limpa tabela de receitas
            conn.commit()
    
    def setUp(self):
        """Executado antes de cada teste"""
        self.app_context = app.app_context()
        self.app_context.push()  # Cria um contexto de aplicação
        self.limpar_tabelas()  # Garante um banco limpo antes de cada teste
    
    def tearDown(self):
        """Executado após cada teste"""
        self.app_context.pop()  # Remove o contexto de aplicação
    
    def criar_usuario_teste(self, email='teste@email.com', senha='senha123', admin=False):
        """Cria um usuário de teste no banco de dados"""
        with conectar_db() as conn:
            cursor = conn.cursor()
            # Cria um hash seguro da senha
            hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
                INSERT INTO usuarios (nome, email, telefone, senha, admin)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Usuário Teste', email, '123456789', hashed, 1 if admin else 0))
            conn.commit()
            return cursor.lastrowid  # Retorna o ID do usuário criado
    
    def criar_receita_teste(self, user_id, titulo='Receita Teste'):
        """Cria uma receita de teste no banco de dados"""
        with conectar_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO receitas (titulo, categoria, ingredientes, preparo, user_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (titulo, 'Categoria', 'Ingredientes', 'Preparo', user_id))
            conn.commit()
            return cursor.lastrowid  # Retorna o ID da receita criada
    
    def login_usuario(self, email, senha):
        """Realiza login de um usuário"""
        return self.client.post('/login', data={
            'email': email,
            'senha': senha
        }, follow_redirects=True)  # Segue redirecionamentos
    




    # =====================================================
    # TESTES DE CADASTRO DE USUÁRIO COM EMAIL JA CADASTRADO
    # =====================================================
    
    def test_cadastro_email_existente(self):
        """Testa tentativa de cadastro com email já existente"""
        with self.client as c:
            # 1. PREPARAÇÃO: Cria um usuário existente para o teste
            self.criar_usuario_teste()
            
            # 2. DADOS DE TESTE: Usa um email que já está cadastrado
            dados = {
                'nome': 'Outro Usuário',
                'email': 'teste333@email.com',  # Email que já existe
                'telefone': '987654321',
                'senha': 'senha123',
                'confirmar_senha': 'senha123'
            }

            print("\n=== O QUE ERA ESPERADO ===")
            print("2. NÃO deve redirecionar para a página de login")
            print("3. Deve permanecer na página de cadastro")

            # 3. EXECUÇÃO: Tenta cadastrar com email repetido
            response = c.post('/cadastrar_usuario', data=dados, follow_redirects=True)
            
            # 4. VERIFICAÇÕES: Mostra resultados no console
            print("\n=== RESULTADOS OBTIDOS ===")
            print(f"Redirecionou para login? {'SIM' if b'Login' in response.data else 'NÃO'}")
            print(f"Permaneceu na página de cadastro? {'SIM' if b'Cadastrar' in response.data else 'NÃO'}")

            # 5. ASSERÇÕES: Verifica o comportamento esperado
            self.assertNotIn(b'Login', response.data, "ERRO: Cadastro com email repetido não deveria ser bem-sucedido")
            self.assertIn(b'Cadastrar', response.data, "ERRO: Deveria permanecer na pág" \
            "ina de cadastro")



    # ===================================================
    # TESTES DE CADASTRO DE USUÁRIO COM SENHAS DIFERENTES
    # ===================================================
    def test_cadastro_senhas_diferentes(self):
        """Testa tentativa de cadastro com senhas diferentes"""
        with self.client as c:
            # 1. DADOS DE TESTE: Cria dados com senhas que não coincidem
            dados = {
                'nome': 'Usuário Teste333',
                'email': 'teste333@email.com',
                'telefone': '333',
                'senha': 'senha123',
                'confirmar_senha': 'senha1234'  # Senha diferente propositalmente
            }

            print("\n=== O QUE ERA ESPERADO ===")
            print("1. NÃO deve redirecionar para a página de login")
            print("2. Deve permanecer na página de cadastro")
            print("3. Deve mostrar mensagem sobre senhas diferentes")

            # 2. EXECUÇÃO: Tenta cadastrar com senhas diferentes
            response = c.post('/cadastrar_usuario', data=dados, follow_redirects=True)
            
            # 3. VERIFICAÇÕES: Mostra resultados no console
            print("\n=== RESULTADOS OBTIDOS ===")
            print(f"Redirecionou para login? {'SIM' if b'Login' in response.data else 'NÃO'}")
            print(f"Permaneceu na página de cadastro? {'SIM' if b'Cadastrar' in response.data else 'NÃO'}")
            print(f"Mensagem sobre senhas diferentes? {'SIM' if b'senhas' in response.data.lower() else 'NÃO'}")

            # 4. ASSERÇÕES: Verifica o comportamento esperado
            self.assertNotIn(b'Login', response.data, "ERRO: Cadastro com senhas diferentes não deveria ser bem-sucedido")
            self.assertIn(b'Cadastrar', response.data, "ERRO: Deveria permanecer na página de cadastro")
            self.assertIn(b'senhas', response.data.lower(), "ERRO: Deveria mostrar mensagem sobre senhas diferentes")

# Ponto de entrada para execução dos testes
if __name__ == '__main__':
    unittest.main(verbosity=2)  # Executa os testes com detalhamento