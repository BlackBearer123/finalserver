from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient, errors
from bson import ObjectId
from transformers import MarianMTModel, MarianTokenizer
import os
from datetime import datetime

# Minimal setup and configuration
app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv("SECRET_KEY", "mysecret")
db_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

# MongoDB Client initialization
try:
    client = MongoClient(db_uri)
    db = client['chat_app']
    users_collection = db['users']
    chat_history_collection = db['chat_history']
except errors.ConnectionError as e:
    print(f"MongoDB connection error: {str(e)}")
    raise

# JWT setup
app.config["JWT_SECRET_KEY"] = app.secret_key
jwt = JWTManager(app)

# Load translation models and tokenizers (with smaller versions)
models = {
    "french": {
        "tokenizer": MarianTokenizer.from_pretrained("Helsinki-NLP/opus-mt-en-fr"),
        "model": MarianMTModel.from_pretrained("Helsinki-NLP/opus-mt-en-fr")
    },
    "german": {
        "tokenizer": MarianTokenizer.from_pretrained("Helsinki-NLP/opus-mt-en-de"),
        "model": MarianMTModel.from_pretrained("Helsinki-NLP/opus-mt-en-de")
    },
    "spanish": {
        "tokenizer": MarianTokenizer.from_pretrained("Helsinki-NLP/opus-mt-en-es"),
        "model": MarianMTModel.from_pretrained("Helsinki-NLP/opus-mt-en-es")
    }
}

@app.route('/save-chat-history', methods=['POST'])
@jwt_required()
def save_chat_history():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        messages = data.get('messages', [])

        if not messages or not isinstance(messages, list):
            return jsonify({"error": "Invalid message format"}), 400

        chat_entry = {
            "user_id": current_user,
            "timestamp": datetime.utcnow(),
            "messages": [{"sender": msg.get("sender"), "text": msg.get("text"), "timestamp": datetime.utcnow()} for msg in messages]
        }

        result = chat_history_collection.insert_one(chat_entry)

        return jsonify({"message": "Chat history saved successfully", "chat_id": str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({"error": f"Failed to save chat history: {e}"}), 500

@app.route('/chat-history', methods=['GET'])
@jwt_required()
def get_chat_history():
    try:
        current_user = get_jwt_identity()
        chat_histories = chat_history_collection.find({"user_id": current_user}).sort("timestamp", -1)

        formatted_histories = [{
            "chat_id": str(chat["_id"]),
            "timestamp": chat["timestamp"].isoformat(),
            "messages": chat["messages"]
        } for chat in chat_histories]

        return jsonify({"chat_histories": formatted_histories}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to fetch chat history: {e}"}), 500

@app.route('/delete-chat', methods=['DELETE'])
@jwt_required()
def delete_chat():
    try:
        current_user = get_jwt_identity()
        chat_id = request.args.get('chat_id')

        if not chat_id:
            return jsonify({"error": "Chat ID is required"}), 400

        result = chat_history_collection.delete_one({"_id": ObjectId(chat_id), "user_id": current_user})

        if result.deleted_count == 0:
            return jsonify({"error": "Chat not found or unauthorized"}), 404

        return jsonify({"message": "Chat deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to delete chat: {e}"}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Username, email, and password are required!"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists!"}), 400

    hashed_password = generate_password_hash(password)
    try:
        users_collection.insert_one({"username": username, "email": email, "password": hashed_password})
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    user = users_collection.find_one({"email": email})
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({"access_token": access_token, "userId": str(user['_id'])}), 200

    return jsonify({"message": "Invalid credentials!"}), 401

@app.route("/translates", methods=["POST"])
def translates():
    data = request.get_json()
    phrase, language = data.get("phrase"), data.get("language")

    if not phrase or not language or language not in models:
        return jsonify({"error": "Invalid input"}), 400

    try:
        tokenizer = models[language]["tokenizer"]
        model = models[language]["model"]
        inputs = tokenizer(phrase, return_tensors="pt", truncation=True, max_length=512)
        translated = model.generate(**inputs)
        translated_phrase = tokenizer.decode(translated[0], skip_special_tokens=True)
        return jsonify({"translatedPhrase": translated_phrase}), 200
    except Exception as e:
        return jsonify({"message": f"Error during translation: {e}"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
