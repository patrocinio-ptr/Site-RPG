from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .models import User

auth = Blueprint("auth", __name__)


@auth.route("/login")
def login():
    return render_template("login.html")


@auth.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash("Confira suas credenciais e tente novamente.")
        return redirect(url_for("auth.login"))

    login_user(user)

    return redirect(url_for("main.profile"))


@auth.route("/signup")
def signup():
    return render_template("signup.html")


@auth.route("/signup", methods=["POST"])
def signup_post():
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(email=email).first()

    if user:
        flash("Endereço de email já existe")
        return redirect(url_for("auth.signup"))

    new_user = User(email=email, username=username, password=generate_password_hash(password, method="sha256"))

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)

    return redirect(url_for("main.index"))


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))
