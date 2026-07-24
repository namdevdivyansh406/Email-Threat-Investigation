from flask import Flask
import os


def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-key"),
        UPLOAD_FOLDER=os.path.join(app.root_path, "uploads"),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        ALLOWED_EXTENSIONS={"eml"},
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from .routes import main

    app.register_blueprint(main)
    return app
