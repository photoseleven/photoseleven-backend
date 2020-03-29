from flask import Flask
import os


def create_app(custom_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    if custom_config is None:
        app.config.from_object(os.getenv('APP_CONFIG'))
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('application.py', silent=True)
    else:
        # load the custom config if passed in
        app.config.from_object(custom_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        os.makedirs(app.config['UPLOADS_DIR'], exist_ok=True)
    except OSError:
        pass

    # a simple page to ping the running app
    @app.route('/ping', methods=['GET'])
    def hello():
        return 'Pong!'

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import gallery
    app.register_blueprint(gallery.bp)

    return app
