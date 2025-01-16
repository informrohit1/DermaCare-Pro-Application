from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import bcrypt
import MySQLdb

app = Flask(__name__)

app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "Flask1234"
app.config['MYSQL_DB'] = "userdatabase"
app.secret_key = 'MY_SECRET_KEY'

mysql_initialized = False  # Flag to ensure database setup runs only once


class RegisterForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired(), Email()])
    password = PasswordField("password", validators=[DataRequired()])
    confirm_password = PasswordField("confirm_password", validators=[
        DataRequired(), EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(), Email()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Login")


def setup_database():
    """
    Creates the database and table if they do not exist.
    """
    global mysql_initialized
    if not mysql_initialized:
        try:
            # Connect without specifying the database
            connection = MySQLdb.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                passwd=app.config['MYSQL_PASSWORD']
            )
            cursor = connection.cursor()

            # Create the database if it doesn't exist
            cursor.execute("CREATE DATABASE IF NOT EXISTS userdatabase")
            connection.commit()

            # Use the created database to set up tables
            cursor.execute("USE userdatabase")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                )
            """)
            connection.commit()
            cursor.close()
            connection.close()
            mysql_initialized = True
        except MySQLdb.Error as e:
            print(f"Error setting up the database: {e}")


@app.before_request
def initialize_database():
    setup_database()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            # Use a connection tied to `userdatabase`
            connection = MySQLdb.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                passwd=app.config['MYSQL_PASSWORD'],
                db=app.config['MYSQL_DB']
            )
            cursor = connection.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, hashed_password))
            connection.commit()
            cursor.close()
            connection.close()
            return redirect(url_for('login'))
        except MySQLdb.Error as e:
            print(f"An error occurred: {e}")
            return "An error occurred while registering the user."
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            # Connect to the database
            connection = MySQLdb.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                passwd=app.config['MYSQL_PASSWORD'],
                db=app.config['MYSQL_DB']
            )
            cursor = connection.cursor()

            # Fetch the user record based on the provided email
            cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            cursor.close()
            connection.close()

            if result:
                hashed_password = result[0]
                # Check if the provided password matches the hashed password
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('login.html', form=form, error="Invalid password. Please try again.")
            else:
                return render_template('login.html', form=form, error="No account found with that email.")
        except MySQLdb.Error as e:
            print(f"An error occurred: {e}")
            return "An error occurred while authenticating the user."

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)
