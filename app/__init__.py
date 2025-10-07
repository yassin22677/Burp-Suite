from flask import Flask, render_template

def create_app():
    app = Flask(__name__)

    # Home route (for dashboard)
    @app.route('/')
    def home():
        return render_template('dashboard.html')

    return app

#from app.views.auth_routes import auth_bp



    # Register blueprints
   # app.register_blueprint(auth_bp)

   
