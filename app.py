from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import Flask, request, render_template, redirect, url_for
import hashlib
import logging

app = Flask(__name__)

@app.route("/")
def get_home_page() -> str:
    """Render the phishing simulation landing page (index.html)."""
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def handle_phishing_submission() -> Any:
    """Process phishing login attempt: hash password, collect behavioral data, log securely."""
    username: Optional[str] = request.form.get("username")
    raw_password: Optional[str] = request.form.get("password")
    
    if not username or not raw_password:
        # Log invalid attempt
        _write_log_entry("INVALID", "", request.remote_addr, "")
        return redirect(url_for("get_simulation_result"))

    hashed_password = _hash_password(raw_password)

    # Collect client IP, user agent, behavioral metrics
    behavioral_data = _collect_behavioral_data(request)

    # Write comprehensive log entry
    _write_log_entry(
        username, 
        hashed_password, 
        request.remote_addr, 
        request.headers.get("User-Agent", ""),
        **behavioral_data
    )

    return redirect(url_for("get_simulation_result"))


@app.route("/result")
def get_simulation_result() -> str:
    """Render educational result page after phishing simulation."""
    return render_template("result.html")


@app.route("/dashboard")
def get_admin_dashboard() -> str:
    """Admin dashboard: Parse logs and render with risk indicators."""
    log_entries: List[Dict[str, Any]] = _parse_log_file()
    return render_template("dashboard.html", logs=log_entries)


def _hash_password(raw_password: str) -> str:
    """Securely hash password using SHA-256."""
    return hashlib.sha256(raw_password.encode("utf-8")).hexdigest()


def _collect_behavioral_data(request) -> Dict[str, str]:
    """Extract behavioral biometrics from form data."""
    return {
        "time_to_submit": request.form.get("timeToSubmit", "0"),
        "avg_typing_speed": request.form.get("avgTypingSpeed", "0"),
        "mouse_entropy": request.form.get("mouseEntropy", "0"),
        "keystroke_count": request.form.get("keystrokeCount", "0"),
        "hints_shown": request.form.get("hintsShown", "0")
    }


def _write_log_entry(
    username: str, 
    hashed_pw: str, 
    ip: str, 
    user_agent: str, 
    time_to_submit: str = "0", 
    avg_typing_speed: str = "0", 
    mouse_entropy: str = "0", 
    keystroke_count: str = "0", 
    hints_shown: str = "0"
) -> None:
    """Append structured log entry to logs.txt."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = (
        f"{timestamp} | {username} | {hashed_pw} | {ip} | {user_agent} | "
        f"{time_to_submit} | {avg_typing_speed} | {mouse_entropy} | "
        f"{keystroke_count} | {hints_shown}\n"
    )
    try:
        with open("logs.txt", "a", encoding="utf-8") as log_file:
            log_file.write(log_line)
    except IOError:
        logging.error("Failed to write log entry")


def _parse_log_file() -> List[Dict[str, Any]]:
    """Safely parse logs.txt into structured data for dashboard."""
    logs: List[Dict[str, Any]] = []
    try:
        with open("logs.txt", "r", encoding="utf-8") as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split(" | ")]
                if len(parts) >= 10:
                    logs.append({
                        "time": parts[0],
                        "user": parts[1],
                        "hash": parts[2][:12] + "..." if len(parts[2]) > 12 else parts[2],
                        "ip": parts[3],
                        "agent": (parts[4][:25] + "...") if len(parts[4]) > 25 else parts[4],
                        "timeToSubmit": parts[5],
                        "typingSpeed": parts[6],
                        "mouseEntropy": parts[7][:6] if len(parts[7]) > 6 else parts[7],
                        "keystrokes": parts[8],
                        "hintsShown": parts[9]
                    })
    except FileNotFoundError:
        pass  # No logs yet
    except Exception as e:
        logging.error(f"Failed to parse log file: {e}")
    return logs


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)

