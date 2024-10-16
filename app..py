from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import bcrypt
from flask import Flask, request
import mysql.connector
import pyotp

app = Flask(__name__)

mydb = None  # Variável global para armazenar a conexão com o banco de dados
codigo = None  # Variável global para armazenar o código de autenticação

# Função para estabelecer uma conexão com o banco de dados MySQL com as informações de acesso (não seguro, apenas para fins didáticos)
def get_db_connection():
    global mydb  # Permite acessar e modificar a variável global 'mydb'
    
    # Verifica se os dados da requisição estão no formato JSON
    if request.is_json:
        # Extrai os dados do JSON
        data = request.get_json()
        host = data.get('host')
        user = data.get('user')
        database = data.get('database')
        password = data.get('password')
        
        # Estabelece a conexão com o banco de dados MySQL usando as informações fornecidas
        mydb = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        
        return f"Conexão bem-sucedida com o banco de dados"
    else:
        return "Erro ao conectar ao banco de dados"

# Rota para realizar o login
@app.route('/login', methods=['POST'])
def login():
    # Estabelece a conexão com o banco de dados ao acessar a rota de login
    get_db_connection()
    
    # Verifica se os dados da requisição estão no formato JSON
    if request.is_json:
        # Extrai os dados de email e senha do JSON
        data = request.get_json()
        email = data.get('email')
        senha = data.get('senha')
    
        # Executa uma consulta no banco de dados para recuperar as informações do usuário com o email fornecido
        cursor = mydb.cursor()
        query = "SELECT * FROM user WHERE email = %s"
        data = (email,)
        cursor.execute(query, data)
        senha_banco = cursor.fetchone()[3]  # Recupera a senha armazenada no banco de dados (assumindo que está na 4ª coluna)
        
        # Compara a senha fornecida com a senha armazenada usando bcrypt
        if bcrypt.checkpw(senha.encode('utf-8'), senha_banco.encode('utf-8')):
            # Envia um email com o código de autenticação se as senhas coincidirem
            send_msg(email)
            return 'Login autorizado! Código de autenticação enviado por email.'   
        else:
            return "Senha incorreta."
    else:
        return "Dados não recebidos corretamente."

# Função para enviar o código de autenticação para o email do usuário
def send_msg(email):
    global codigo  # Permite acessar e modificar a variável global 'codigo'
    
    # Configurações para se conectar ao servidor de email (SMTP)
    host = "smtp.gmail.com"
    port = 587 
    login = "<email-test>"
    senha = "<senha gerda pelo google>"  # Senha gerada pelo Google para permitir login seguro

    # Estabelece a conexão com o servidor SMTP
    server = smtplib.SMTP(host, port)
    server.ehlo()  # Identifica o cliente para o servidor SMTP
    server.starttls()  # Inicia uma conexão criptografada (TLS)
    server.login(login, senha)  # Faz login na conta de email

    # Gera um código de autenticação TOTP baseado no tempo
    secret = pyotp.random_base32()  # Gera uma chave secreta aleatória em Base32
    totp = pyotp.TOTP(secret)  # Cria um objeto TOTP com a chave gerada
    codigo = totp.now()  # Gera o código de autenticação válido para o tempo atual
    
    # Monta o conteúdo do email
    body = f"<b>Código para autorizar o login: </b><b>{codigo}</b>"
    email_msg = MIMEMultipart()
    email_msg['From'] = login
    email_msg['To'] = email 
    email_msg['Subject'] = "Código de Autenticação"
    email_msg.attach(MIMEText(body, 'html'))  # Anexa o corpo do email em formato HTML
    
    # Envia o email com o código de autenticação
    server.sendmail(email_msg['From'], email_msg['To'], email_msg.as_string())
    server.quit()  # Encerra a conexão com o servidor SMTP

    return 'Email enviado com sucesso!'

# Rota para verificar se o código de autenticação está correto
@app.route('/verify', methods=["POST"])
def verify():
    if request.is_json:
        # Extrai o código enviado pelo usuário do JSON
        data = request.get_json()
        codigo_request = data.get('codigo')
        
        # Compara o código recebido com o código gerado
        if codigo == codigo_request:
            return "Login autorizado!"
        else:
            return "Código incorreto."
    else:
        return "Dados não recebidos corretamente."

# Inicia o servidor Flask
if __name__ == '__main__':
    app.run(debug=True)
