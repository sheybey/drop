from flask import Flask, render_template, redirect, flash, abort
from flask_login import LoginManager, current_user
from flask_login.mixins import UserMixin, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields import PasswordField, StringField, DateField, SelectField
from wtforms.validators import InputRequired, ValidationError, Optional
from os import path, mkdir, stat
from datetime import date


class DefaultConfiguration:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///drop.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'hello'
    UPLOAD_DIR = 'uploads'


app = Flask(__name__)
app.config.from_object(DefaultConfiguration)
app.config.from_pyfile('drop.cfg', silent=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app)


class Token(UserMixin, db.Model):

    class Permissions:
        none = 0
        upload = 1
        admin = 2

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(512), nullable=False, unique=True)
    permission = db.Column(
        db.Integer,
        nullable=False,
        default=Permissions.none
    )
    expires = db.Column(db.DateTime)
    files = db.relationship('File', backref=db.backref('token'), lazy=True)

    @property
    def admin(self):
        return self.permission >= self.Permissions.admin

    @property
    def upload(self):
        return self.permission >= self.Permissions.upload

    @property
    def file_count(self):
        return File.query.filter_by(token_id=self.id).count()

    def visible_files(self):
        return filter(
            lambda f: f.visible_to(self),
            File.query.all()
        )


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(
        db.Integer,
        db.ForeignKey('token.id'),
        nullable=False
    )
    name = db.Column(db.String(1024), nullable=False, unique=True)
    public = db.Column(db.Boolean, nullable=False)

    def visible_to(self, token):
        return self.public or token.admin or self.token.id == token.id

    def url(self):
        return url_to('get', name=self.name)

    def human_size(self):
        size = stat(path.join(app.config['UPLOAD_DIR'], self.name)).st_size
        k = 1024.0
        m = k * 1024
        g = m * 1024
        if size > g:
                return "{} GiB".format(round(size / g, 2))
        if size > m:
                return "{} MiB".format(round(size / m, 2))
        if size > k:
                return "{} KiB".format(round(size / k, 2))
        return "{} bytes".format(size)



class AnonymousUser(AnonymousUserMixin):
    token = None
    permission = 0
    expires = None
    admin = False
    upload = False
    file_count = 0

    def visible_files(self):
        return File.query.filter_by(public=True).all()


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def user_loader(id):
    return Token.query.get(int(id))


class MessageValidator:
    def __init__(self, message):
        self.message = message


class AfterToday(MessageValidator):
    def __call__(self, form, field):
        if field.data <= date.today():
            raise ValidationError(self.message)


class NewToken(MessageValidator):
    def __call__(self, form, field):
        if Token.query.filter_by(token=field.data).limit(1).count() > 0:
            raise ValidationError(self.message)


class LoginForm(FlaskForm):
    token = PasswordField(
        'Token',
        validators=[InputRequired('Incorrect token')]
    )


class UploadForm(FlaskForm):
    pass


class CreateTokenForm(FlaskForm):
    token = StringField(
        'Token',
        validators=[
            InputRequired('Specify a token to create'),
            NewToken('This token already exists')
        ]
    )
    permission = SelectField(
        'Permissions',
        choices=(
            ('View only', Token.Permissions.none),
            ('Upload', Token.Permissions.upload),
            ('Admin', Token.Permissions.admin)
        ),
        validators=[InputRequired('Specify a permission level')]
    )
    expires = DateField(
        'Expiration date', validators=[
            Optional(),
            AfterToday('You cannot create an expired token')
        ]
    )


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        for token in Token.query.all():
            if form.token.data == token.token:
                login_manager.login_user(token)
                flash('Logged in')
                return redirect(url_for('index'))
        flash('Incorrect token', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    login_manager.logout_user()
    flash('Logged out')
    return redirect(url_for('index'))


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        pass
    return render_template('upload.html', form=form)


@app.route('/tokens')
def tokens():
    if not current_user.admin:
        return redirect(url_for('login'))
    return render_template('tokens.html', tokens=Token.query.all())


@app.route('/tokens/<token>')
def files(token):
    if not current_user.admin:
        return redirect(url_for('login'))
    return render_template(
        'token.html',
        token=Token.query.filter_by(token=token).first_or_404()
    )


@app.route('/tokens/create', methods=['GET', 'POST'])
def create_token():
    if not current_user.admin:
        return redirect(url_for('login'))
    form = CreateTokenForm()
    if form.validate_on_submit():
        token = Token(
            token=form.token.data,
            permission=form.permission.data,
            expires=form.expires.data
        )
        db.session.add(token)
        db.session.commit()
        flash('Token `{}\' created'.format(token.token), 'success')
        return redirect(url_for('tokens'))
    return render_template('create_token.html', form=form)


@app.route('/get/<name>')
def get(name):
    file = File.query.filter_by(name=name).first_or_404()
    if not file.visible_to(current_user):
        abort(404)
    return send_from_directory(app.config['UPLOAD_DIR'], file.name)


@app.route('/debug')
def debug():
    return render_template('debug.html')


@app.cli.group(name="db")
def dbcli():
    """Create or drop the database."""
    pass


@dbcli.command()
def create():
    """Create the database."""
    db.create_all()
    db.session.add(Token(
        token='please and thank you',
        permission=Token.Permissions.admin
    ))
    db.session.commit()


@dbcli.command()
def drop():
    """Drop the database."""
    db.drop_all()


@app.cli.command()
def uploads():
    """Create the uploads folder."""
    if not path.isdir(app.config['UPLOAD_DIR']):
        mkdir(app.config['UPLOAD_DIR'])
