from flask import current_app as app
from flask import request, jsonify, json
from werkzeug.security import generate_password_hash, check_password_hash
from db import db
import uuid
from flask import Blueprint


app = Blueprint("auth", __name__)


@app.route("/", methods=["GET"])
def hello():
    return "WORKING SUCCESSFULLY"


# For Login-----------------------------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        if db.accounts.find_one({"username": username}):
            return jsonify({"error": "Username already exists"}), 400

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        db.accounts.insert_one({"username": username, "password": hashed_password})
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user = db.accounts.find_one({"username": username})

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid username or password"}), 401

        token = str(user["_id"])

        model = db.Models.find_one(
    {"user_id": str(user["_id"]), "status": 1},
    sort=[("_id", -1)]  # Sort by `_id` in descending order (newest first)
)

        if model:
            model_id = model["_id"]
        else:
            model_id = None

        return (
            jsonify(
                {
                    "message": "Login Successfully",
                    "model_id": str(model_id),
                    "user-id": token,
                    "username": user["username"] if user else None,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/request-reset-password", methods=["POST"])
def request_reset_password():
    try:
        username = request.form.get("username")

        if not username:
            return jsonify({"error": "Username is required"}), 400

        user = db.accounts.find_one({"username": username})
        print(username)
        if user:
            reset_token = str(uuid.uuid4())
            db.accounts.insert_one({"username": username, "reset_token": reset_token})
            return (
                jsonify(
                    {
                        "message": "Password reset requested. Check your email for the reset link.",
                        "reset_token": reset_token,
                    }
                ),
                200,
            )
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        new_password = request.form.get("new_password")
        reset_token = request.form.get("reset_token")

        if not reset_token or not new_password:
            return jsonify({"error": "Reset token and new password are required"}), 400

        reset_entry = db.accounts.find_one({"reset_token": reset_token})
        if reset_entry:
            hashed_password = generate_password_hash(
                new_password, method="pbkdf2:sha256"
            )
            db.accounts.update_one(
                {"username": reset_entry["username"]},
                {"$set": {"password": hashed_password}},
            )
            db.accounts.delete_one({"reset_token": reset_token})
            return jsonify({"message": "Password has been reset successfully!"}), 200
        else:
            return jsonify({"error": "Invalid or expired reset token"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
