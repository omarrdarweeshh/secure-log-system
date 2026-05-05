import os
import json
import uuid
import boto3
import logging
import watchtower
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
AWS_REGION     = os.getenv("AWS_REGION", "eu-north-1")
S3_BUCKET      = os.getenv("S3_BUCKET", "secure-log-system-bucket")
CW_LOG_GROUP   = os.getenv("CW_LOG_GROUP", "/secure-log-system")
CW_LOG_STREAM  = os.getenv("CW_LOG_STREAM", "app-logs")

# ──────────────────────────────────────────────
# AWS CLIENTS (uses EC2 IAM Role automatically)
# ──────────────────────────────────────────────
s3_client  = boto3.client("s3", region_name=AWS_REGION)
cw_client  = boto3.client("logs", region_name=AWS_REGION)

# ──────────────────────────────────────────────
# CLOUDWATCH LOGGING SETUP
# ──────────────────────────────────────────────
cw_handler = watchtower.CloudWatchLogHandler(
    log_group=CW_LOG_GROUP,
    stream_name=CW_LOG_STREAM,
    boto3_client=cw_client
)
cw_handler.setLevel(logging.INFO)

logger = logging.getLogger("secure-log-system")
logger.setLevel(logging.INFO)
logger.addHandler(cw_handler)
logger.addHandler(logging.StreamHandler())  # also print to console

# ──────────────────────────────────────────────
# SIMPLE IN-MEMORY USER STORE (prototype)
# In production this would be a database
# ──────────────────────────────────────────────
USERS = {
    "admin":  {"password": "admin123",  "role": "admin"},
    "user1":  {"password": "user123",   "role": "user"},
    "shared": {"password": "shared123", "role": "shared"},
}

# Active sessions: token -> {user, role}
sessions = {}

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def create_log_event(event_type, user_id, status, details=""):
    """Create a structured log entry."""
    return {
        "log_id":     str(uuid.uuid4()),
        "event_type": event_type,
        "user_id":    user_id,
        "status":     status,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "details":    details,
        "source_ip":  request.remote_addr
    }

def save_log_to_s3(log_entry):
    """Upload a log entry as a JSON object to S3."""
    try:
        key = f"logs/{log_entry['event_type']}/{log_entry['log_id']}.json"
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(log_entry, indent=2),
            ContentType="application/json",
            ServerSideEncryption="AES256"   # encryption at rest
        )
        logger.info(f"[S3] Log saved: {key}")
        return key
    except Exception as e:
        logger.error(f"[S3] Failed to save log: {e}")
        return None

def log_event(event_type, user_id, status, details=""):
    """Create, save to S3, and send to CloudWatch."""
    entry = create_log_event(event_type, user_id, status, details)
    s3_key = save_log_to_s3(entry)
    logger.info(json.dumps({**entry, "s3_key": s3_key}))
    return entry

def require_auth(roles=None):
    """Decorator: checks session token and optional role."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token or token not in sessions:
                log_event("unauthorized_access", "unknown", "blocked",
                          f"No valid token for {request.path}")
                return jsonify({"error": "Unauthorized"}), 401
            session = sessions[token]
            if roles and session["role"] not in roles:
                log_event("access_denied", session["user"], "blocked",
                          f"Role {session['role']} not allowed for {request.path}")
                return jsonify({"error": "Forbidden"}), 403
            request.current_user = session
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Simple HTML dashboard."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure Log System</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        h1   { color: #232f3e; }
        .card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px;
                padding: 20px; margin: 16px 0; }
        .endpoint { background: #232f3e; color: #fff; padding: 4px 8px;
                    border-radius: 4px; font-family: monospace; }
        .badge-get  { background: #28a745; color:#fff; padding:2px 6px; border-radius:4px; font-size:12px; }
        .badge-post { background: #007bff; color:#fff; padding:2px 6px; border-radius:4px; font-size:12px; }
        ul { line-height: 2; }
      </style>
    </head>
    <body>
      <h1>🔐 Secure Cloud Log Management System</h1>
      <div class="card">
        <h2>System Status</h2>
        <p>✅ Backend running | Region: <strong>eu-north-1</strong></p>
      </div>
      <div class="card">
        <h2>API Endpoints</h2>
        <ul>
          <li><span class="badge-post">POST</span> <span class="endpoint">/login</span> — authenticate and get token</li>
          <li><span class="badge-post">POST</span> <span class="endpoint">/logout</span> — invalidate session</li>
          <li><span class="badge-post">POST</span> <span class="endpoint">/simulate-event</span> — trigger a log event</li>
          <li><span class="badge-get">GET</span>  <span class="endpoint">/get-logs</span> — list logs from S3 (admin only)</li>
          <li><span class="badge-get">GET</span>  <span class="endpoint">/health</span> — system health check</li>
        </ul>
      </div>
      <div class="card">
        <h2>Demo Accounts</h2>
        <ul>
          <li><strong>admin</strong> / admin123 — full access</li>
          <li><strong>user1</strong> / user123 — limited access</li>
          <li><strong>shared</strong> / shared123 — shared-recipient</li>
        </ul>
      </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/health")
def health():
    """Health check endpoint for monitoring."""
    return jsonify({
        "status":    "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "region":    AWS_REGION,
        "services":  {"s3": S3_BUCKET, "cloudwatch": CW_LOG_GROUP}
    })


@app.route("/login", methods=["POST"])
def login():
    """Authenticate user, return session token."""
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = USERS.get(username)
    if not user or user["password"] != password:
        log_event("login_attempt", username or "unknown", "failed",
                  "Invalid credentials")
        return jsonify({"error": "Invalid username or password"}), 401

    token = str(uuid.uuid4())
    sessions[token] = {"user": username, "role": user["role"]}
    log_event("login_attempt", username, "success", f"Role: {user['role']}")
    return jsonify({"token": token, "role": user["role"], "message": "Login successful"})


@app.route("/logout", methods=["POST"])
@require_auth()
def logout():
    """Invalidate session token."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user  = sessions.pop(token, {}).get("user", "unknown")
    log_event("logout", user, "success")
    return jsonify({"message": "Logged out successfully"})


@app.route("/simulate-event", methods=["POST"])
@require_auth()
def simulate_event():
    """
    Simulate various security events for demo/testing.
    Accepts: { "event_type": "failed_login" | "api_call" | "error" | "suspicious" }
    """
    data       = request.get_json() or {}
    event_type = data.get("event_type", "api_call")
    user       = request.current_user["user"]

    allowed_events = ["failed_login", "api_call", "error",
                      "suspicious_activity", "data_access"]
    if event_type not in allowed_events:
        return jsonify({"error": f"Unknown event type. Use: {allowed_events}"}), 400

    details = data.get("details", f"Simulated {event_type} by {user}")
    entry   = log_event(event_type, user, "simulated", details)
    return jsonify({"message": "Event logged", "log": entry})


@app.route("/get-logs", methods=["GET"])
@require_auth(roles=["admin"])
def get_logs():
    """List recent log files from S3 (admin only)."""
    try:
        prefix   = request.args.get("prefix", "logs/")
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=prefix,
            MaxKeys=50
        )
        objects = response.get("Contents", [])
        logs = []
        for obj in objects:
            logs.append({
                "key":           obj["Key"],
                "size_bytes":    obj["Size"],
                "last_modified": obj["LastModified"].isoformat()
            })
        log_event("get_logs", request.current_user["user"], "success",
                  f"Listed {len(logs)} log files")
        return jsonify({"count": len(logs), "logs": logs})
    except Exception as e:
        logger.error(f"[get-logs] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/get-log/<log_id>", methods=["GET"])
@require_auth(roles=["admin", "user"])
def get_single_log(log_id):
    """Fetch a specific log file content from S3."""
    try:
        prefix   = f"logs/"
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=prefix,
            MaxKeys=200
        )
        key = None
        for obj in response.get("Contents", []):
            if log_id in obj["Key"]:
                key = obj["Key"]
                break
        if not key:
            return jsonify({"error": "Log not found"}), 404

        obj     = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        content = json.loads(obj["Body"].read().decode("utf-8"))
        log_event("view_log", request.current_user["user"], "success",
                  f"Viewed log: {key}")
        return jsonify(content)
    except Exception as e:
        logger.error(f"[get-log] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
