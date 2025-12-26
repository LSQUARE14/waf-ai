from flask import Flask
from flask_cors import CORS
from app.services.mcp_server import start_mcp_server

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    CORS(app)

    start_mcp_server()

    from .routes import main
    app.register_blueprint(main)

    return app
