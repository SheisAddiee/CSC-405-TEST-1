from flask import Flask

def create_app():
    app = Flask(__name__)
    
    from . import auth
    from . import api
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)
    
    return app