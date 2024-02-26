import os
import os.path as op
import bcrypt
import requests
import json
from flask_admin import Admin
from flask_sqlalchemy import SQLAlchemy

from flask import Flask, render_template, url_for, redirect, request
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt

UPLOAD_FOLDER = 'static'
app = Flask(__name__, static_folder='static')
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
app.config['FLASK_ADMIN_SWATCH'] = 'cosmo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\737215\\Databases\\Weather.db'  # Change to your SQLite database path
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
admin = Admin(app)
try:
    os.mkdir(app.config['UPLOAD_FOLDER'])
except FileExistsError:
    pass

API_KEY = "1201365bcdc548109ad91758242302"
aqi = "yes"

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define your routes
@app.route('/')
@app.route('/home')
def option():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):  # Use bcrypt for password checking
            login_user(user)
            return redirect(url_for('option'))  # Redirect to the appropriate route after login
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registration.html')

@app.route('/weather', methods=['GET', 'POST'])
def weather():
    if request.method == 'POST':
        city_name = request.form['city']
        url = f"http://api.weatherapi.com/v1/current.json?key={API_KEY}&q={city_name}&aqi={aqi}"
        result = requests.get(url)
        wdata = json.loads(result.text)

        location_name = wdata["location"]["name"]
        location_country = wdata["location"]["country"]
        location_lat = wdata["location"]["lat"]
        location_lon = wdata["location"]["lon"]

        # Current weather data
        temperature_celsius = wdata["current"]["temp_c"]
        wind_mph = wdata["current"]["wind_mph"]
        humidity = wdata["current"]["humidity"]
        cloud = wdata["current"]["cloud"]
        us_epa_index = wdata["current"]["air_quality"]["us-epa-index"]

        return render_template('weather.html',
                               location_name=location_name,
                               location_country=location_country,
                               location_lat=location_lat,
                               location_lon=location_lon,
                               temperature_celsius=temperature_celsius,
                               wind_mph=wind_mph,
                               humidity=humidity,
                               cloud=cloud,
                               us_epa_index=us_epa_index)

    return render_template('weather.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
