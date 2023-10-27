import smtplib

from flask import Flask, flash, redirect, render_template, url_for
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, UserMixin, login_required, login_user,
                         logout_user)
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

db = SQLAlchemy()
app = Flask(__name__,
            static_url_path='/static')
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'newsletters.with.love@gmail.com'
app.config['MAIL_PASSWORD'] = 'wdpj uywv jjkf xbom'

db.init_app(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class SendForm(FlaskForm):
    name = StringField('Name')
    email = EmailField('Email')
    submit = SubmitField('Send')


class RegisterFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_username = User.query.filter_by(
            username=username.data).first()

        if existing_username:
            flash('This username already exists. Please try another one', 'danger')
            raise ValidationError(
                'This username already exists. Please try another one')


class LoginFrom(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


@app.route('/', methods=['GET', 'POST'])
def home():
    form = SendForm()
    if form.validate_on_submit():
        email = form.email.data
        subject = "Now, you are in our team!"
        message_body = "Congratulations, now we will send you top movies every week! Thanks for being with us."
        msg = Message(
            subject, sender='newsletters.with.love@gmail.com', recipients=[email])
        msg.body = message_body
        try:
            mail.send(msg)
            flash('You have been subscribed to our email newsletters', 'success')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'danger')
        return redirect("/")
    return render_template('home.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginFrom()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterFrom()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
