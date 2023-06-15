from flask import Blueprint, redirect, url_for, request
from flask_login import login_user, login_required, logout_user
import os
import requests

from . import db
from .models import User

auth = Blueprint("auth", __name__)


@auth.route("/login")
def login():
    redirect_uri = request.host_url + "callback"
    discord_client_id = os.environ.get("DISCORD_CLIENT_ID")
    discord_auth_url = f"https://discord.com/api/oauth2/authorize?client_id={discord_client_id}&redirect_uri={redirect_uri}&response_type=code&scope=identify"  # noqa
    return redirect(discord_auth_url)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@auth.route("/callback")
def callback():
    code = request.args.get("code")
    discord_client_id = os.environ.get("DISCORD_CLIENT_ID")
    discord_client_secret = os.environ.get("DISCORD_CLIENT_SECRET")
    data = {
        "client_id": discord_client_id,
        "client_secret": discord_client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": request.host_url + "callback",
        "scope": "identify",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
    access_token = token_response.json()["access_token"]

    user_response = requests.get(
        "https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {access_token}"}
    )
    user_data = user_response.json()

    if access_token:
        user = User.query.filter_by(discord_id=user_data["id"]).first()

        avatar_url = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}"

        if user is None:
            user = User(discord_id=user_data["id"], username=user_data["username"], avatar=avatar_url)
            db.session.add(user)
        else:
            user.username = user_data["username"]
            user.avatar = avatar_url

        db.session.commit()
        login_user(user)
        return redirect(url_for("main.profile"))
    else:
        return "Failed to obtain access token"
