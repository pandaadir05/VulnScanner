# scanner/webgui.py

import sys
import os

# Add the root project directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import login_dvwa_session  # Now the import should work

from flask import Flask, render_template, request, redirect, url_for
from .scanner import scan_url, results as global_results
from .scanner import init_scanner  # if you have a plugin system or similar
from scanner.main import login_dvwa_session  # or whichever function logs in if needed

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("url")
    do_login = request.form.get("login") == "true"
    chosen_checks = request.form.getlist("checks")  
    # e.g., ["sqli", "xss", "cmdi", ...]

    # Clear old results (global list or however you store them)
    global_results.clear()

    # Optionally init scanner or load plugins
    init_scanner()

    # If user wants to login:
    if do_login:
        # Create a requests.Session() with DVWA login
        session = login_dvwa_session(base_url="http://localhost:8080")
    else:
        session = None

    # "Scan" with or without session 
    # If you have toggles for each check, pass them along or filter checks
    scan_url(target_url, session=session, checks=chosen_checks)
    
    return redirect(url_for("show_results"))

@app.route("/results", methods=["GET"])
def show_results():
    return render_template("results.html", results=global_results)

def run_gui():
    app.run(host="0.0.0.0", port=5000, debug=True)
