rom flask import Flask, request, jsonify
import psycopg2
import bcrypt
import traceback
import jwt
from datetime import datetime
from flask import request, jsonify

app = Flask(_name_)
SECRET_KEY = 'M@Ch@v@SecreT!2024#123'

# Dados de conexão à base de dados
DB_HOST = "127.0.0.1"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASSWORD = "1234"

# Função para criar a conexão com o PostgreSQL
def conectar_bd():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        print("Conexão com a base de dados bem-sucedida.")
        return conn
    except Exception as e:
        print(f"Erro na conexão com a base de dados: {e}")
        raise Exception(f"Erro ao conectar à base de dados: {e}")

# Função para encriptar a palavra-passe
def encriptar_palavra_pass(palavra_pass):
    salt = bcrypt.gensalt()  # Gera um salt
    hashed_pass = bcrypt.hashpw(palavra_pass.encode('utf-8'), salt)  # Encripta a palavra-passe
    return hashed_pass.decode('utf-8')  # Retorna como string

# Rota para registar um novo utilizador
@app.route('/inserir_utilizador', methods=['POST'])
def inserir_utilizador():
    try:
        data = request.get_json()

        nome = data.get('nome')
        palavra_pass = data.get('pass')

        if not nome or not palavra_pass:
            return jsonify({"message": "Nome e palavra-passe são obrigatórios"}), 400

        palavra_pass_encriptada = encriptar_palavra_pass(palavra_pass)

        conn = conectar_bd()
        cursor = conn.cursor()

        cursor.execute("CALL registar_utilizador(%s, %s)", (nome, palavra_pass_encriptada))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Utilizador inserido com sucesso!"}), 201

    except Exception as e:
        print(f"Erro inesperado: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro inesperado: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        nome = data.get('nome')
        palavra_pass = data.get('pass')

        if not nome or not palavra_pass:
            return jsonify({"message": "Nome e palavra-passe são obrigatórios"}), 400

        conn = conectar_bd()
        cursor = conn.cursor()

        # Verificar se o usuário existe e obter o ID
        cursor.execute("SELECT login_utilizador(%s, %s)", (nome, palavra_pass))
        id_utilizador = cursor.fetchone()

        if not id_utilizador or id_utilizador[0] is None:
            return jsonify({"message": "Utilizador não encontrado"}), 404

        id_utilizador = id_utilizador[0]

        # Obter a palavra-passe armazenada e o nome de usuário associado
        cursor.execute("SELECT palavra_pass, nome FROM utilizadores WHERE id = %s", (id_utilizador,))
        resultado = cursor.fetchone()
        if not resultado:
            return jsonify({"message": "Erro ao obter informações do utilizador"}), 500

        hash_armazenado, username = resultado

        # Verificar a palavra-passe
        if not bcrypt.checkpw(palavra_pass.encode('utf-8'), hash_armazenado.encode('utf-8')):
            return jsonify({"message": "Palavra-passe incorreta"}), 401

        cursor.close()
        conn.close()

        # Retornar o ID do usuário e o nome de usuário
        return jsonify({
            "message": "Login realizado com sucesso!",
            "user_id": id_utilizador,
            "username": username
        }), 200

    except Exception as e:
        print(f"Erro inesperado: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro inesperado: {str(e)}"}), 500


def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token é obrigatório"}), 401

        try:
            # Remove o prefixo "Bearer " se existir
            token = token.split()[1] if " " in token else token
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = decoded_token["user_id"]  # Adiciona user_id ao pedido
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token inválido"}), 401

        return f(*args, **kwargs)

    return decorator

@app.route('/inserir_evento_e_utilizador', methods=['POST'])
def receber_evento():
    try:
        dados = request.get_json()

        if not dados:
            return jsonify({"message": "Nenhum dado foi recebido"}), 400

        tipo_evento = dados.get('type')
        descricao = dados.get('description')
        localizacao = dados.get('location')
        data_evento = dados.get('event_date')
        hora_evento = dados.get('event_time')
        prazo_registro_data = dados.get('registration_deadline_date')
        prazo_registro_hora = dados.get('registration_deadline_time')
        lugares = dados.get('seats')
        is_free = True if dados.get('is_free') == 'true' else False
        preco = dados.get('price')
        id_utilizador = dados.get('id')

        conn = conectar_bd()
        cursor = conn.cursor()

        cursor.execute(""" 
        CALL adicionar_evento(
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            tipo_evento, descricao, localizacao, data_evento, hora_evento, 
            prazo_registro_data, prazo_registro_hora, lugares, is_free, preco, id_utilizador
        ))

        conn.commit()

        # Obter o id do evento inserido
        cursor.execute("SELECT event_id FROM all_events ORDER BY event_id DESC LIMIT 1")
        event_id = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        return jsonify({"message": "Evento inserido com sucesso!", "event_id": event_id}), 201

    except Exception as e:
        print(f"Erro ao processar os dados recebidos: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao processar os dados: {str(e)}"}), 500


@app.route('/api/events', methods=['GET'])
def get_events():
    """
    Endpoint para listar todos os eventos ou eventos filtrados por user_id.
    """
    try:
        # Obtém o user_id como parâmetro de consulta. Se não existir, será None
        user_id = request.args.get('user_id')

        conn = conectar_bd()
        cursor = conn.cursor()

        # Se o user_id for fornecido, filtra os eventos desse usuário
        if user_id:
            cursor.execute("SELECT * FROM all_events WHERE user_id = %s", (user_id,))
        else:  # Caso contrário, retorna todos os eventos
            cursor.execute("SELECT * FROM all_events")

        eventos = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        eventos_json = [dict(zip(colunas, evento)) for evento in eventos]

        # Conversão de datas e horas
        for evento in eventos_json:
            if evento.get("event_date"):
                try:
                    evento["event_date"] = datetime.strptime(evento["event_date"], "%Y-%m-%d").strftime('%d/%m/%Y')
                except ValueError:
                    evento["event_date"] = evento.get("event_date")  # Caso falhe, mantém a string original

            if evento.get("event_time"):
                try:
                    evento["event_time"] = datetime.strptime(evento["event_time"], "%H:%M:%S").strftime('%H:%M')
                except ValueError:
                    evento["event_time"] = evento.get("event_time")  # Caso falhe, mantém a string original

        cursor.close()
        conn.close()

        return jsonify(eventos_json), 200

    except Exception as e:
        print(f"Erro ao recuperar eventos: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao recuperar eventos: {str(e)}"}), 500


@app.route('/api/events/user/<int:user_id>', methods=['GET'])
def get_events_by_user(user_id):
    """
    Endpoint para listar eventos filtrados por user_id.
    """
    try:
        conn = conectar_bd()
        cursor = conn.cursor()

        # Filtra os eventos pelo user_id
        cursor.execute("SELECT * FROM all_events WHERE user_id = %s", (user_id,))

        eventos = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        eventos_json = [dict(zip(colunas, evento)) for evento in eventos]

        # Conversão de datas e horas
        for evento in eventos_json:
            if evento.get("event_date"):
                try:
                    evento["event_date"] = datetime.strptime(evento["event_date"], "%Y-%m-%d").strftime('%d/%m/%Y')
                except ValueError:
                    evento["event_date"] = evento.get("event_date")  # Caso falhe, mantém a string original

            if evento.get("event_time"):
                try:
                    evento["event_time"] = datetime.strptime(evento["event_time"], "%H:%M:%S").strftime('%H:%M')
                except ValueError:
                    evento["event_time"] = evento.get("event_time")  # Caso falhe, mantém a string original

        cursor.close()
        conn.close()

        return jsonify(eventos_json), 200

    except Exception as e:
        print(f"Erro ao recuperar eventos: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao recuperar eventos: {str(e)}"}), 500


@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event_by_id(event_id):
    """
    Endpoint para retornar detalhes de um evento específico usando o event_id.
    """
    try:
        conn = conectar_bd()
        cursor = conn.cursor()

        # Filtra os eventos pelo event_id
        cursor.execute("SELECT * FROM all_events WHERE event_id = %s", (event_id,))

        evento = cursor.fetchone()

        if evento is None:
            return jsonify({"message": "Evento não encontrado"}), 404

        colunas = [desc[0] for desc in cursor.description]
        evento_json = dict(zip(colunas, evento))

        # Conversão de datas e horas
        if evento_json.get("event_date"):
            try:
                evento_json["event_date"] = datetime.strptime(evento_json["event_date"], "%Y-%m-%d").strftime('%d/%m/%Y')
            except ValueError:
                evento_json["event_date"] = evento_json.get("event_date")  # Caso falhe, mantém a string original

        if evento_json.get("event_time"):
            try:
                evento_json["event_time"] = datetime.strptime(evento_json["event_time"], "%H:%M:%S").strftime('%H:%M')
            except ValueError:
                evento_json["event_time"] = evento_json.get("event_time")  # Caso falhe, mantém a string original

        cursor.close()
        conn.close()

        return jsonify(evento_json), 200

    except Exception as e:
        print(f"Erro ao recuperar evento: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao recuperar evento: {str(e)}"}), 500

@app.route('/inscricoes', methods=['POST'])
def inscrever_em_evento():
    try:
        data = request.get_json()

        utilizador_id = data.get('utilizador_id')
        evento_id = data.get('evento_id')

        if not utilizador_id or not evento_id:
            return jsonify({"message": "utilizador_id e evento_id são obrigatórios"}), 400

        conn = conectar_bd()
        cursor = conn.cursor()

        # Verificar se o utilizador já está inscrito neste evento
        cursor.execute(
            """
            SELECT COUNT(*) 
            FROM inscricoes_eventos 
            WHERE utilizador_id = %s AND evento_id = %s
            """, (utilizador_id, evento_id)
        )
        if cursor.fetchone()[0] > 0:
            return jsonify({"message": "O utilizador já está inscrito neste evento."}), 400

        # Inserir a inscrição
        cursor.execute(
            """
            INSERT INTO inscricoes_eventos (utilizador_id, evento_id)
            VALUES (%s, %s)
            """,
            (utilizador_id, evento_id)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Inscrição realizada com sucesso!"}), 201

    except Exception as e:
        print(f"Erro ao inscrever no evento: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao inscrever no evento: {str(e)}"}), 500


@app.route('/eventos/<int:evento_id>/inscricao', methods=['DELETE'])
def cancelar_inscricao(evento_id):
    try:
        utilizador_id = request.args.get('user_id')

        if not utilizador_id:
            return jsonify({"message": "user_id é obrigatório"}), 400

        conn = conectar_bd()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM inscricoes_eventos
            WHERE utilizador_id = %s AND evento_id = %s
            """,
            (utilizador_id, evento_id)
        )

        if cursor.rowcount == 0:
            return jsonify({"message": "Inscrição não encontrada"}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Inscrição cancelada com sucesso!"}), 200

    except Exception as e:
        print(f"Erro ao cancelar inscrição: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao cancelar inscrição: {str(e)}"}), 500



@app.route('/inscricoes/verificar', methods=['GET'])
def verificar_inscricao():
    try:
        utilizador_id = request.args.get('utilizador_id')
        evento_id = request.args.get('evento_id')

        if not utilizador_id or not evento_id:
            return jsonify({"message": "utilizador_id e evento_id são obrigatórios"}), 400

        conn = conectar_bd()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*) > 0
            FROM inscricoes_eventos
            WHERE utilizador_id = %s AND evento_id = %s
            """,
            (utilizador_id, evento_id)
        )

        inscrito = cursor.fetchone()[0]

        # Resposta mais explícita
        if inscrito:
            return jsonify({"message": "Usuário inscrito no evento"}), 200
        else:
            return jsonify({"message": "Usuário não inscrito no evento"}), 200

    except Exception as e:
        print(f"Erro ao verificar inscrição: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao verificar inscrição: {str(e)}"}), 500


@app.route('/inscricoes/utilizador/<int:utilizador_id>', methods=['GET'])
def listar_inscricoes_por_utilizador(utilizador_id):
    try:
        conn = conectar_bd()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT e.*
            FROM eventos e
            INNER JOIN inscricoes_eventos ie ON e.id = ie.evento_id
            WHERE ie.utilizador_id = %s
            """,
            (utilizador_id,)
        )

        eventos = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        eventos_json = [dict(zip(colunas, evento)) for evento in eventos]

        cursor.close()
        conn.close()

        return jsonify(eventos_json), 200

    except Exception as e:
        print(f"Erro ao listar inscrições: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao listar inscrições: {str(e)}"}), 500

@app.route('/inscricoes/verificar/<int:utilizador_id>/<int:evento_id>', methods=['GET'])
def is_user_subscribed_to_event(utilizador_id, evento_id):
    try:
        conn = conectar_bd()
        cursor = conn.cursor()

        # Verifica se o utilizador está inscrito no evento
        cursor.execute(
            """
            SELECT COUNT(*) > 0
            FROM inscricoes_eventos
            WHERE utilizador_id = %s AND evento_id = %s
            """,
            (utilizador_id, evento_id)
        )

        inscrito = cursor.fetchone()[0]

        # Responde com "True" ou "False"
        return jsonify({"is_subscribed": inscrito}), 200

    except Exception as e:
        print(f"Erro ao verificar inscrição: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao verificar inscrição: {str(e)}"}), 500


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
def delete_event(event_id):
    """
    Endpoint para apagar um evento pelo seu ID.
    """
    try:
        conn = conectar_bd()
        cursor = conn.cursor()

        # Apagar o evento com base no ID
        cursor.execute("DELETE FROM eventos WHERE id = %s", (event_id,))

        # Commit da operação
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"message": "Evento não encontrado"}), 404

        cursor.close()
        conn.close()

        return jsonify({"message": f"Evento com ID {event_id} apagado com sucesso!"}), 200

    except Exception as e:
        print(f"Erro ao apagar o evento: {str(e)}")
        traceback.print_exc()
        return jsonify({"message": f"Erro ao apagar o evento: {str(e)}"}), 500



if _name_ == '_main_':
    app.run(debug=True)
