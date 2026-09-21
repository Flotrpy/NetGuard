"""Deliberately vulnerable Flask app (test fixture, never deploy)."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + uid + "'")  # SQL injection
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()  # command injection


@app.route("/run")
def run():
    subprocess.call(request.args["cmd"], shell=True)  # command injection
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # unsafe deserialization


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))  # unsafe YAML


@app.route("/file")
def read_file():
    return open(request.args["name"]).read()  # path traversal


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text  # SSRF + TLS off


@app.route("/go")
def go():
    return redirect(request.args["next"])  # open redirect


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # weak hash


def make_reset_token():
    return str(random.randint(0, 999999))  # insecure randomness


if __name__ == "__main__":
    app.run(debug=True)  # debug enabled
