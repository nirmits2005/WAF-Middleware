"""
Demo web application protected by the WAF middleware.

Run:  python app.py            (block mode)
      WAF_MODE=monitor python app.py   (log-only mode)
"""

import os
from flask import Flask, jsonify, request

from waf import WAFMiddleware


def create_app(log_file="logs/waf.log", mode=None):
    app = Flask(__name__)

    @app.get("/")
    def index():
        return jsonify(message="Welcome - this site is protected by a WAF")

    @app.get("/search")
    def search():
        return jsonify(results=f"You searched for: {request.args.get('q', '')}")

    @app.post("/login")
    def login():
        return jsonify(status="received", user=request.form.get("username", ""))

    @app.get("/file")
    def get_file():
        return jsonify(file=request.args.get("name", ""), content="(demo file content)")

    @app.post("/comment")
    def comment():
        data = request.get_json(silent=True) or {}
        return jsonify(status="comment saved", comment=data.get("text", ""))

    @app.get("/waf/stats")
    def waf_stats():
        return jsonify(dict(waf.stats))

    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    waf = WAFMiddleware(app.wsgi_app, log_file=log_file,
                        mode=mode or os.environ.get("WAF_MODE", "block"))
    app.wsgi_app = waf
    app.waf = waf
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
