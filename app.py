import os
import secrets
import time

from flask import Flask, abort, redirect, render_template, request, session, url_for

from encrypt import run_demo_check


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() == "true",
)

if os.environ.get("APP_ENV", "").lower() == "production" and not os.environ.get(
    "FLASK_SECRET_KEY"
):
    raise RuntimeError("FLASK_SECRET_KEY must be configured in production.")

ATTEMPT_TTL_SECONDS = 5 * 60


def _browser_id() -> str:
    browser_id = session.get("browser_id")
    if not browser_id:
        browser_id = secrets.token_urlsafe(32)
        session["browser_id"] = browser_id
    return browser_id


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _check_csrf() -> None:
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400, description="Invalid or missing CSRF token.")


@app.get("/")
def home():
    result = session.pop("demo_result", None)
    return render_template("index.html", csrf_token=_csrf_token(), result=result)


@app.post("/auth/start")
def start_authentication():
    _check_csrf()
    if request.form.get("consent") != "yes":
        abort(400, description="Consent is required before starting verification.")

    attempt_id = secrets.token_urlsafe(32)
    _browser_id()
    session["attempt_id"] = attempt_id
    session["attempt_expires_at"] = time.time() + ATTEMPT_TTL_SECONDS
    return redirect(url_for("mock_provider", attempt_id=attempt_id))


@app.get("/mock-provider")
def mock_provider():
    attempt_id = request.args.get("attempt_id", "")
    now = time.time()
    expires_at = session.get("attempt_expires_at")
    valid_attempt = (
        bool(session.get("browser_id"))
        and session.get("attempt_id") == attempt_id
        and isinstance(expires_at, (int, float))
        and expires_at > now
    )

    if not valid_attempt:
        abort(410, description="This verification session has expired or is invalid.")

    return render_template(
        "mock_provider.html",
        csrf_token=_csrf_token(),
        attempt_id=attempt_id,
    )


@app.post("/mock-provider/complete")
def complete_mock_verification():
    _check_csrf()
    attempt_id = request.form.get("attempt_id", "")
    outcome = request.form.get("outcome")
    if outcome not in {"verified", "cancelled"}:
        abort(400, description="Invalid mock-provider outcome.")

    expires_at = session.get("attempt_expires_at")
    valid_attempt = (
        bool(session.get("browser_id"))
        and session.get("attempt_id") == attempt_id
        and isinstance(expires_at, (int, float))
        and expires_at > time.time()
    )

    if not valid_attempt:
        abort(410, description="This verification session has expired or was already used.")

    session.pop("attempt_id", None)
    session.pop("attempt_expires_at", None)

    if outcome == "verified":
        # The browser only says "run the check". The result comes from the
        # server-side simulation, never from a browser-supplied success flag.
        check = run_demo_check()
        passed = check["ret"] == "y" and check["response_verified"]
        steps = check["steps"] + (["UIDAI response signature verified"] if check["response_verified"] else [])
        session["demo_result"] = {
            "verified": passed,
            "steps": steps,
            "message": (
                "Bank check passed (ret=y). Every step ran on fictional data and keys; "
                "no Aadhaar identity was checked and this is not authentication."
                if passed
                else f"Bank check failed (ret=n, err={check['err']}). This is a simulation."
            ),
        }
    else:
        session["demo_result"] = {
            "verified": False,
            "steps": [],
            "message": "The mock verification was cancelled.",
        }
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
