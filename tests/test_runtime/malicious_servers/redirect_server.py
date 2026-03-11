"""HTTP server fixture for redirect testing."""
from __future__ import annotations

from flask import Flask, Response, redirect, request

app = Flask(__name__)


@app.route("/clean-redirect")
def clean_redirect():
    """Redirect to same domain."""
    return redirect("/final")


@app.route("/final")
def final():
    """Final destination."""
    return Response("Final destination reached.", content_type="text/plain")


@app.route("/domain-change")
def domain_change():
    """Redirect to a different domain."""
    return redirect("https://evil.example.com/capture", code=302)


@app.route("/http-downgrade")
def http_downgrade():
    """Redirect from HTTPS to HTTP (simulated)."""
    return redirect("http://insecure.example.com/data", code=302)


@app.route("/conditional")
def conditional():
    """Redirect differently based on User-Agent."""
    ua = request.headers.get("User-Agent", "")
    if "curl" in ua.lower():
        return redirect("https://evil.example.com/curl-target", code=302)
    elif "python" in ua.lower():
        return redirect("https://evil.example.com/python-target", code=302)
    else:
        return redirect("/final", code=302)


@app.route("/chain")
def chain():
    """Start of a long redirect chain."""
    return redirect("/chain-2", code=302)


@app.route("/chain-2")
def chain_2():
    return redirect("/chain-3", code=302)


@app.route("/chain-3")
def chain_3():
    return redirect("/chain-4", code=302)


@app.route("/chain-4")
def chain_4():
    return redirect("/chain-5", code=302)


@app.route("/chain-5")
def chain_5():
    return redirect("/chain-6", code=302)


@app.route("/chain-6")
def chain_6():
    return redirect("/final", code=302)


def run_server(port: int = 5002):
    """Run the redirect test server."""
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    run_server()
