import click
from flask import current_app, g
from flask.cli import with_appcontext
from flask_pymongo import PyMongo
from werkzeug.security import check_password_hash, generate_password_hash


def get_db():
    if 'db' not in g:
        mongo = PyMongo(current_app)
        g.db = mongo.db
        g.db_client = mongo.cx

    return g.db


def close_db(e=None):
    g.pop('db', None)
    db_client = g.pop('db_client', None)

    if db_client is not None:
        db_client.close()


def init_app(app):
    app.teardown_appcontext(close_db)

