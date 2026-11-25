import subprocess
from flask import request


def pingHost():
    host = request.args.get("host")
    subprocess.call("ping -c 1 " + host, shell=True)