from photoseleven import create_app
from photoseleven.db import get_db
import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture
def app():

    app = create_app('config.TestingConfig')

    with app.app_context():
        get_db().users.insert_one({'username': 'test', 'password': generate_password_hash('test')})

    yield app

    with app.app_context():
        get_db().users.delete_many({})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()
