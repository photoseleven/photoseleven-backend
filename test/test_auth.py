import datetime
from flask import url_for
import json
import jwt
from photoseleven.auth import AuthErrors
from photoseleven.db import get_db
import pytest
from werkzeug.security import check_password_hash


def test_json_only(client, app):
    with app.app_context():
        assert client.post(url_for('auth.users_manipulation'),
                           data=json.dumps({'username': 'a', 'password': 'password'})).status_code == 415


@pytest.mark.parametrize(('username', 'password', 'status_code', 'error_message'),
                         (('test', 'test', 401, AuthErrors.ERR_AUTH_USER_EXISTS),
                          ('', 'test', 401, AuthErrors.ERR_AUTH_NO_USERNAME),
                          ('a', '', 401, AuthErrors.ERR_AUTH_NO_PASSWORD),
                          ('a', 'a', 201, '')))
def test_register(client, app, username, password, status_code, error_message):
    with app.app_context():
        response = client.post(url_for('auth.users_manipulation'),
                               data=json.dumps({'username': username, 'password': password}),
                               content_type='application/json')

        assert response.status_code == status_code

        resp_json = response.get_json()
        if 'err_code' in resp_json:
            assert not resp_json['success']
            assert response.get_json()['err_code'] == error_message
        else:
            assert resp_json['success']
            assert get_db().users.find_one({'username': username}) is not None


@pytest.mark.parametrize(('username', 'password', 'new_password', 'status_code', 'error_message'),
                         (('test', 'test', 'test2', 200, ''),
                          ('', 'test', '', 401, AuthErrors.ERR_AUTH_NO_USERNAME),
                          ('a', '', '', 401, AuthErrors.ERR_AUTH_NO_PASSWORD),
                          ('a', 'a', '', 412, AuthErrors.ERR_AUTH_NO_NEW_PASSWORD),
                          ('a', 'a', 'a', 401, AuthErrors.ERR_AUTH_USER_NOT_EXIST),
                          ('test', 'test2', 'test3', 401, AuthErrors.ERR_AUTH_WRONG_PASSWORD),
                          ('test', 'test', 'test', 412, AuthErrors.ERR_AUTH_SAME_NEW_PASS)))
def test_modify_password(client, app, username, password, new_password, status_code, error_message):
    with app.app_context():
        response = client.put(url_for('auth.users_manipulation'),
                              data=json.dumps({'username': username,
                                               'password': password,
                                               'new_password': new_password}),
                              content_type='application/json')

        assert response.status_code == status_code

        resp_json = response.get_json()
        if 'err_code' in resp_json:
            assert not resp_json['success']
            assert resp_json['err_code'] == error_message
        else:
            assert resp_json['success']
            user = get_db().users.find_one({'username': username})
            assert check_password_hash(user['password'], new_password)


@pytest.mark.parametrize(('username', 'password', 'status_code', 'error_message'),
                         (('test', 'test', 200, ''),
                          ('', 'test', 401, AuthErrors.ERR_AUTH_NO_USERNAME),
                          ('a', '', 401, AuthErrors.ERR_AUTH_NO_PASSWORD),
                          ('a', 'a', 401, AuthErrors.ERR_AUTH_USER_NOT_EXIST),
                          ('test', 'test2', 401, AuthErrors.ERR_AUTH_WRONG_PASSWORD)))
def test_delete(client, app, username, password, status_code, error_message):
    with app.app_context():
        response = client.delete(url_for('auth.users_manipulation'),
                                 data=json.dumps({'username': username,
                                                  'password': password}),
                                 content_type='application/json')

        assert response.status_code == status_code

        resp_json = response.get_json()
        if 'err_code' in resp_json:
            assert not resp_json['success']
            assert resp_json['err_code'] == error_message
        else:
            assert resp_json['success']
            assert get_db().users.find_one({'username': username}) is None


def test_users_wrong_method(client, app):
    with app.app_context():
        response = client.get(url_for('auth.users_manipulation'),
                              data=json.dumps({'username': 'username',
                                               'password': 'password'}),
                              content_type='application/json')

        assert response.status_code == 405


@pytest.mark.parametrize(('username', 'password', 'status_code', 'error_message'),
                         (('test', 'test', 200, ''),
                          ('', 'test', 401, AuthErrors.ERR_AUTH_NO_USERNAME),
                          ('a', '', 401, AuthErrors.ERR_AUTH_NO_PASSWORD),
                          ('a', 'a', 401, AuthErrors.ERR_AUTH_USER_NOT_EXIST),
                          ('test', 'test2', 401, AuthErrors.ERR_AUTH_WRONG_PASSWORD)))
def test_login(client, app, username, password, status_code, error_message):
    with app.app_context():
        response = client.post(url_for('auth.login'),
                               data=json.dumps({'username': username,
                                                'password': password}),
                               content_type='application/json')

        assert response.status_code == status_code

        resp_json = response.get_json()
        if 'err_code' in resp_json:
            assert not resp_json['success']
            assert resp_json['err_code'] == error_message
        else:
            assert resp_json['success']
            decoded = jwt.decode(resp_json['token'], app.config['SECRET_KEY'], algorithms='HS256')
            assert decoded is not None
            assert decoded['username'] == username


def test_login_required(client, app):
    with app.app_context():
        response = client.post(url_for('auth.login'),
                               data=json.dumps({'username': 'test',
                                                'password': 'test'}),
                               content_type='application/json')

        assert response.status_code == 200
        resp_json = response.get_json()
        assert resp_json['success']

        token = resp_json['token']

        # OK case
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

        # No header
        response = client.get(url_for('auth.login_ping'))
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_NO_AUTH_HEADER

        # Wrong header
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'ASDA'})
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_NO_AUTH_HEADER

        # Token expired
        fake_token = jwt.encode({'username': 'test', 'exp': datetime.datetime.utcnow() - datetime.timedelta(seconds=1)},
                                app.config['SECRET_KEY'],
                                algorithm='HS256').decode('UTF-8')
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'Bearer {fake_token}'})
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_TOKEN_EXPIRED

        # Invalid token
        fake_token = jwt.encode({'username': 'test', 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10)},
                                'FAKE_KEY',
                                algorithm='HS256').decode('UTF-8')
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'Bearer {fake_token}'})
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_TOKEN_INVALID

        # No username
        fake_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10)},
                                app.config['SECRET_KEY'],
                                algorithm='HS256').decode('UTF-8')
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'Bearer {fake_token}'})
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_NO_USERNAME

        # Wrong username
        fake_token = jwt.encode({'username': 'test2', 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10)},
                                app.config['SECRET_KEY'],
                                algorithm='HS256').decode('UTF-8')
        response = client.get(url_for('auth.login_ping'), headers={'Authorization': f'Bearer {fake_token}'})
        assert response.status_code == 401
        assert 'success' in response.get_json() and not response.get_json()['success']
        assert 'err_code' in response.get_json() and response.get_json()[
            'err_code'] == AuthErrors.ERR_AUTH_USER_NOT_EXIST
