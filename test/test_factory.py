from photoseleven import create_app
import os

def test_config():
    assert not create_app().testing
    assert create_app('config.TestingConfig').testing


def test_test_config(app):
    assert app.testing


def test_ping(client):
    response = client.get('/ping')
    assert response.data == b'Pong!'

def test_dirs_exist(app):
    assert os.path.isdir(app.config['UPLOADS_DIR'])
    assert os.path.isdir(app.instance_path)
