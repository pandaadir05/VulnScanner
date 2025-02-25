import sys
import os

# Add the root project directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import login_dvwa_session, get_vulnerability_pages
from flask import Flask, render_template, request, redirect, url_for
from .scanner import scan_url, results as global_results
from .scanner import init_scanner

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("url")
    do_login = request.form.get("login") == "true"
    chosen_checks = request.form.getlist("checks")
    global_results.clear()
    init_scanner()
    
    if do_login:
        session = login_dvwa_session(base_url=target_url)
        vuln_pages = get_vulnerability_pages(session, target_url)
        for page in vuln_pages:
            print(f"[*] Scanning {page}")
            scan_url(page, session=session, checks=chosen_checks, do_crawl=True)
    else:
        scan_url(target_url, session=None, checks=chosen_checks, do_crawl=True)
    
    return redirect(url_for("show_results"))

@app.route("/results", methods=["GET"])
def show_results():
    return render_template("results.html", results=global_results)

def run_gui():
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    run_gui()
