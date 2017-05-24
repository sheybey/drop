from flask import Flask, render_template, redirect, flash, abort, url_for, \
    request, escape, send_from_directory, jsonify, session
from markupsafe import Markup
from werkzeug.utils import secure_filename
from flask_login import LoginManager, current_user
from flask_login.mixins import UserMixin, AnonymousUserMixin
from flask_login.utils import login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms.fields import PasswordField, StringField, DateField, \
    SelectField, BooleanField
from wtforms.validators import InputRequired, DataRequired, ValidationError, \
    Optional
from os import path, mkdir, stat, unlink, urandom
from datetime import date
from tokenize import tokenize, untokenize, NAME, OP, EQUAL, STRING, \
    ENCODING, NEWLINE, NL, ENDMARKER, open as token_open
from functools import wraps


class DefaultConfiguration:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///drop.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = b'hello'
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

    @property
    def expired(self):
        return self.expires is not None and self.expires <= date.today()

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
        nullable=False,
        default=lambda: current_user
    )
    name = db.Column(db.String(1024), nullable=False, unique=True)
    public = db.Column(db.Boolean, nullable=False)

    def visible_to(self, token):
        return self.public or token.admin or self.token.id == token.id

    def url(self):
        return url_for('get', name=self.name)

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

    def delete(self):
        unlink(path.join(app.config['UPLOAD_DIR'], self.name))


class AnonymousUser(AnonymousUserMixin):
    token = None
    permission = 0
    expires = None
    expired = False
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


class UniqueName(MessageValidator):
    def __call__(self, form, field):
        name = secure_filename(field.data.filename)
        if name == '':
            raise ValidationError(self.message['empty'])
        if path.exists(path.join(app.config['UPLOAD_DIR'], name)):
            raise ValidationError(self.message['exists'])


class LoginForm(FlaskForm):
    token = PasswordField(
        'Token',
        validators=[InputRequired('Missing token.')]
    )


class UploadForm(FlaskForm):
    file = FileField(
        'File',
        validators=[
            FileRequired(message='Specify a file to upload'),
            UniqueName(message={
                'empty': 'Invalid filename.',
                'exists': 'This file already exists.'
            })
        ]
    )
    public = BooleanField('Public')
    owner = SelectField(
        'Owner',
        coerce=int,
        validators=[
            Optional(),
            InputRequired('Invalid owner.')
        ]
    )


class CreateTokenForm(FlaskForm):
    token = StringField(
        'Token',
        validators=[
            InputRequired('Specify a token to create.'),
            NewToken('This token already exists.')
        ]
    )
    permission = SelectField(
        'Permissions',
        choices=(
            (Token.Permissions.none, 'View only'),
            (Token.Permissions.upload, 'Upload'),
            (Token.Permissions.admin, 'Admin')
        ),
        coerce=int,
        validators=[InputRequired('Specify a permission level.')]
    )
    expires = DateField(
        'Expiration date',
        validators=[
            Optional(),
            DataRequired('Invalid date.'),
            AfterToday('You cannot create an expired token.')
        ]
    )


def login_required(message, category='error'):
    def wrap(f):
        @wraps(f)
        def check_login(**kwargs):
            if not current_user.is_authenticated:
                session['next'] = url_for(f.__name__, **kwargs)
                flash(message, category)
                return redirect(url_for('login'))
            return f(**kwargs)
        return check_login
    return wrap


def perm_required(permission, message, category='error'):
    def wrap(f):
        @wraps(f)
        def check_perms(**kwargs):
            if not current_user.permission >= permission:
                flash(message, category)
                return redirect(url_for('index'))
            return f(**kwargs)
        return check_perms
    return wrap


@app.before_request
def check_token():
    if current_user.expired:
        logout_user()
        flash('This token has expired.', 'error')
        return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        for token in Token.query.all():
            if form.token.data == token.token:
                if token.expired:
                    flash('This token has expired.', 'error')
                    return redirect(url_for('index'))
                login_user(token)
                flash('Logged in.', 'success')
                return redirect(session.pop('next', url_for('index')))
        flash('Incorrect token.', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required('You must log in to upload files.')
@perm_required(
    permission=Token.Permissions.upload,
    message='You are not allowed to upload files.'
)
def upload():
    form = UploadForm()

    if current_user.admin:
        form.owner.choices = (
            ((0, 'Me'),) +
            tuple(
                (token.id, token.token)
                for token in Token.query.all()
                if token.id != current_user.id
            )
        )
    else:
        form.owner.choices = []

    if form.validate_on_submit():
        file = form.file.data
        name = secure_filename(file.filename)  # This is checked in UniqueName
        file.save(path.join(app.config['UPLOAD_DIR'], name))
        db.session.add(File(
            name=name,
            public=form.public.data,
            token=(
                current_user
                if not current_user.admin or not form.owner.data
                # None is fine because it defaults to current_user
                else Token.query.get(form.owner.data)
            )
        ))
        db.session.commit()
        if request.args.get('json', False):
            return jsonify({'uploaded': name})
        flash('File `{}\' uploaded.'.format(name), 'success')
        return redirect(url_for('index'))
    if request.args.get('json', False):
        errors = []
        for field in form.errors:
            for error in form.errors[field]:
                errors.append(error)
        return jsonify({'errors': errors}), 400
    return render_template('upload.html', form=form)


@app.route('/file/delete', methods=['POST'])
def delete_file():
    if not current_user.admin:
        abort(401)
    try:
        file = File.query.get_or_404(int(request.form['file']))
    except ValueError:  # keyerror from request.form is handled by werkzeug
        abort(400)
    name = file.name
    file.delete()
    db.session.delete(file)
    db.session.commit()
    if request.args.get('json', False):
        return jsonify({'deleted': name})
    flash('File `{}\' deleted.'.format(name), 'success')
    return redirect(url_for('index'))


@app.route('/tokens')
@login_required('You must log in to view tokens.')
@perm_required(
    permission=Token.Permissions.admin,
    message='You are not allowed to view tokens.'
)
def tokens():
    return render_template('tokens.html', tokens=Token.query.all())


@app.route('/tokens/<int:token_id>')
@login_required('You must log in to view tokens.')
@perm_required(
    permission=Token.Permissions.admin,
    message='You are not allowed to view tokens.'
)
def files(token_id):
    if not current_user.admin:
        return redirect(url_for('login'))
    return render_template(
        'token.html',
        token=Token.query.get_or_404(token_id)
    )


@app.route('/tokens/delete', methods=['POST'])
def delete_token():
    if not current_user.admin:
        abort(401)
    try:
        token = Token.query.get_or_404(int(request.form['token']))
        # taking a copy ensures all files are iterated over.
        for file in token.files[:]:
            file.token = current_user
            db.session.add(file)
    except ValueError:
        abort(400)
    t = token.token
    db.session.delete(token)
    db.session.commit()
    if request.args.get('json', False):
        return jsonify({'deleted': t})
    flash('Token `{}\' deleted.'.format(t), 'success')
    return redirect(url_for('tokens'))


@app.route('/tokens/create', methods=['GET', 'POST'])
@login_required('You must log in to create a token.')
@perm_required(
    permission=Token.Permissions.admin,
    message='You are not allowed to create a token.'
)
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
        flash('Token `{}\' created.'.format(token.token), 'success')
        return redirect(url_for('tokens'))
    return render_template('create_token.html', form=form)


@app.route('/get/<name>')
def get(name):
    file = File.query.filter_by(name=name).first_or_404()
    if not file.visible_to(current_user):
        if current_user.is_authenticated:
            flash('You are not allowed to view this file.', 'error')
            return redirect('index')
        else:
            flash('You must log in to view this file.', 'error')
            session['next'] = url_for('get', name=name)
            return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_DIR'], file.name)


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
    """
    Create the uploads folder.
    """
    if not path.isdir(app.config['UPLOAD_DIR']):
        mkdir(app.config['UPLOAD_DIR'])


@app.cli.command()
def secret_key():
    """
    Randomly generate a new secret key, creating the config file if necessary.
    """

    assign = False
    name = None
    result = []
    new_key = urandom(24)
    f = None
    found = False

    try:
        with open('drop.cfg', 'rb') as f:
            tokens = tokenize(f.readline)

            for t in tokens:
                token = t.type
                source = t.string
                op_type = t.exact_type

                if token == NAME:
                    name = source
                elif token == OP:
                    assign = op_type == EQUAL
                elif token == ENCODING:
                    encoding = source

                if token == STRING and assign and name == 'SECRET_KEY':
                    result.append((STRING, repr(new_key)))
                    found = True
                else:
                    result.append((token, source))

        if not found:
            for pair in (
                (NEWLINE, '\n'),
                (NAME, 'SECRET_KEY'),
                (OP, '='),
                (STRING, repr(new_key)),
                (NEWLINE, '\n')
            ):
                result.insert(-1, pair)

    except FileNotFoundError:
        result = [
            (ENCODING, 'utf-8'),
            (NAME, 'SECRET_KEY'),
            (OP, '='),
            (STRING, repr(new_key)),
            (NEWLINE, '\n'),
            (ENDMARKER, '')
        ]

    with open('drop.cfg', 'wb') as f:
        f.write(untokenize(result))


if __name__ == '__main__':
    app.run(debug=True, use_debugger=False, use_reloader=False)
