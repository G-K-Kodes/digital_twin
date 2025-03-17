from flask import Flask
from routes.network import network_bp
from routes.predict import predict_bp
from flask_cors import CORS
from flask_socketio import SocketIO

app = Flask(__name__)
CORS(app)

app.register_blueprint(network_bp, url_prefix='/network')
app.register_blueprint(predict_bp, url_prefix='/predict')
socketio = SocketIO(app, cors_allowed_origins="*")

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)