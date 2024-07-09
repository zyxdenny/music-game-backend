from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import json

app = Flask(__name__)
with open("config.json") as config_file:
    config = json.load(config_file)
    
app.config['SECRET_KEY'] = config['app_secret_key']
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{config['db_username']}:{config['db_password']}@{config['host']}:{config['port']}/{config['db_name']}"
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user_logins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)




@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Invalid username"}), 401

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(username=username, password_hash=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": "Error: " + str(e)}), 500




@app.route('/api/delete', methods=['POST'])
def delete():
    data = request.get_json()
    id = data['id']
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "User not found"}), 401

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deletion successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error: " + str(e)}), 500




@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = User.query.filter_by(username=username).first()
    if user and hashed_password == user.password_hash:
        session['user_id'] = user.id
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# @app.route('/logout', methods=['POST'])
# def logout():
#     session.pop('user_id', None)
#     return jsonify({"message": "Logout successful"}), 200

if __name__ == '__main__':
    # db.create_all()
    app.run(debug=True)

