from flask import Flask
from flask_cors import CORS
from api.routes.network import network_bp
from api.routes.predict import predict_bp

app = Flask(__name__)
CORS(app)

app.register_blueprint(network_bp, url_prefix='/network')
app.register_blueprint(predict_bp, url_prefix='/predict')

if __name__ == '__main__':
    app.run(debug=True, port=5000)