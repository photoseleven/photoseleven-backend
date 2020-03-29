from photoseleven.db import get_db
from pymongo.errors import ConnectionFailure
import pytest


def test_get_db(app):
    with app.app_context():
        db = get_db()
        assert db is get_db()
