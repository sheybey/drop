from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)


class DefaultConfiguration:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///drop.db'
    SECRET_KEY = 'hello'


login_manager = LoginManager(app)
db = SQLAlchemy(app)


@app.cli.group(name="db")
def dbcli():
    pass


@dbcli.command
def create():
    db.create_all()


@dbcli.command
def drop():
    db.drop_all()
