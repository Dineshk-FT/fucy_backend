from flask import current_app as app
from flask import request, jsonify, json
from werkzeug.security import generate_password_hash, check_password_hash
from db import db
import uuid
from flask import Blueprint
from datetime import datetime, timedelta
from bson import ObjectId
import random
import string
from app.__init__ import send_email

def generate_license_key():
    """Generate a unique license key in the format: XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    while True:
        key = '-'.join(
            ''.join(random.choices(chars, k=4)) 
            for _ in range(4)
        )
        # Ensure the key is unique
        if not db.accounts.find_one({"license_key": key}):
            return key

app = Blueprint("auth", __name__)


@app.route("/", methods=["GET"])
def hello():
    return "WORKING SUCCESSFULLY"

# Registration API
@app.route("/register", methods=["POST"])
def register():
    try:
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        org = request.form.get("org")
        password = request.form.get("password")
        license_type = request.form.get("license_type")  # 'trial', '1month', etc.
        role = request.form.get("role")
        email=request.form.get("email")

        if not all([firstname, lastname, org, password, role, email]):
            return jsonify({"error": "All fields (firstname, lastname, org, password, role) are required"}), 400

        username = f"{firstname}.{lastname}".lower()
        existing_account = db.accounts.find_one({"email": email})
        existing_user = db.accounts.find_one({"username": username})
        existing_org = db.accounts.find_one({"org": org})

        if existing_account and existing_user and existing_org:
            return jsonify({"error": "User already has an account"}), 400

        # Determine license durations
        duration_mapping = {
            "trial": 14,        # 2 weeks trial
            "1month": 30,
            "3months": 90,
            "6months": 180,
            "1year": 365
        }

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Check if user has already used trial license by email+org
        existing_trial = db.accounts.find_one({
            "firstname": firstname,
            "lastname": lastname,
            "email":email,
            "org": org,
            "license_type": "trial"
        })

        # If requested license_type is trial and they have used trial before, deny
        if license_type == "trial" and existing_trial:
            return jsonify({"error": "Trial license already used. Please choose a paid license."}), 400

        # If no license_type provided or invalid, assign trial if not used before; else require paid
        if not license_type or license_type not in duration_mapping:
            if existing_trial:
                return jsonify({"error": "Trial license already used. Please choose a paid license."}), 400
            else:
                license_type = "trial"

        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=duration_mapping[license_type])

        # Generate unique license key
        license_key = generate_license_key()
        
        # Create user
        db.accounts.insert_one({
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "email":email,
            "org": org,
            "password": hashed_password,
            "role": role,
            "license_type": license_type,
            "license_key": license_key,
            "license_start": start_date,
            "license_end": end_date
        })

        return jsonify({
            "message": f"User registered successfully with {license_type} license!",
            "license_key": license_key
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check-user-status", methods=["POST"])
def check_user_status():
    try:
        email = request.form.get("email")  # No lower() - case sensitive
        org = request.form.get("org")      # No lower() - case sensitive

        if not email or not org:
            return jsonify({"error": "Email and Organization are required"}), 400

        # First check if email exists in any organization (case sensitive)
        user_with_email = db.accounts.find_one({
            "$or": [
                {"email": email},  # Exact case match
                {"username": email}  # Exact case match
            ]
        })

        if not user_with_email:
            return jsonify({
                "exists": False,
                "trialUsed": False,
                "trialExpired": False,
                "license_end": None,
                "message": "User not found"
            }), 200

        # Check if this user exists in the specified organization (case sensitive)
        user = db.accounts.find_one({
            "$and": [
                {"$or": [{"email": email}, {"username": email}]},
                {"org": org}  # Exact case match
            ]
        })

        if not user:
            return jsonify({
                "exists": False,
                "trialUsed": False,
                "trialExpired": False,
                "license_end": None,
                "message": "User not found in this organization"
            }), 200

        # License check logic remains the same
        if user.get("license_type") == "trial":
            license_end = user.get("license_end")
            current_time = datetime.utcnow()
            
            trial_expired = False
            if license_end:
                trial_expired = license_end < current_time

            return jsonify({
                "exists": True,
                "trialUsed": True,
                "trialExpired": trial_expired,
                "license_end": license_end.isoformat() if license_end else None,
                "message": "Valid trial license"
            }), 200

        return jsonify({
            "exists": True,
            "trialUsed": False,
            "trialExpired": False,
            "license_end": None,
            "message": "Valid user with no trial license"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/send-verification-otp", methods=["POST"])
def send_verification_otp():
    try:
        email = request.form.get("email")
        print("Email:", email)
        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Generate random 6-digit OTP
        otp = random.randint(100000, 999999)

        db.verification.insert_one({
            "email": email,
            "otp": str(otp),
            "expires_at": datetime.utcnow() + timedelta(minutes=10)
        })

        send_email(
            to=email,
            subject="Your Verification OTP",
            body=f"Your OTP is: {otp}. It expires in 10 minutes."
        )

        return jsonify({"message": "Verification OTP sent to email"}), 200

    except Exception as e:
        print("❌ ERROR:", str(e))  # <-- SEE THE ERROR IN CONSOLE
        return jsonify({"error": str(e)}), 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.form.get("email")
    otp = request.form.get("otp")

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    record = db.verification.find_one({"email": email, "otp": otp})

    if not record:
        return jsonify({"error": "Invalid OTP"}), 400

    if record["expires_at"] < datetime.utcnow():
        return jsonify({"error": "OTP expired"}), 400

    # Optionally mark as verified or remove OTP
    db.verification.delete_one({"_id": record["_id"]})

    return jsonify({"message": "Email verified"}), 200



# Upgrade License API
@app.route("/upgrade-license", methods=["POST"])
def upgrade_license():
    try:
        user_id = request.form.get("user_id")
        license_type = request.form.get("license_type")

        if not user_id or not license_type:
            return jsonify({"error": "User ID and license type are required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        duration_mapping = {
            "1month": 30,
            "3months": 90,
            "6months": 180,
            "1year": 365
        }

        if license_type not in duration_mapping:
            return jsonify({"error": "Invalid license type"}), 400

        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=duration_mapping[license_type])

        db.accounts.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "license_type": license_type,
                    "license_start": start_date,
                    "license_end": end_date
                }
            }
        )
        return jsonify({"message": f"License upgraded to {license_type}"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Login API with license check
@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user = db.accounts.find_one({
            "$or": [
                {"username": username},
                {"email": username}  # username might be email
            ]
        })

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid username or password"}), 401

        user_type = user.get("user_type")
        organization = user.get("org", "")  # Using org instead of organization
        license_end = user.get("license_end")
        current_date = datetime.utcnow()
        is_admin = user_type == "admin"

        # Check if license is valid
        license_status = "active"
        if not is_admin:  # Skip license check for admins
            if not license_end:
                license_status = "inactive"
            elif current_date > license_end:
                license_status = "expired"

        # If the user is NOT an admin AND (has no license OR license expired) AND has no organization -> block login.
        if not is_admin:
            if license_status in ["inactive", "expired"] and not organization:
                return jsonify({
                    "error": "Access denied. No valid license and no organization assigned.",
                    "license_status": license_status
                }), 403

        # If license is invalid, prompt for upgrade (unless admin)
        if license_status in ["inactive", "expired"] and not is_admin:
            return jsonify({
                "error": "License expired. Please upgrade to continue.",
                "license_status": license_status
            }), 403

        token = str(user["_id"])

        model = db.Models.find_one(
            {"user_id": str(user["_id"]), "status": 1},
            sort=[("_id", -1)]
        )

        model_id = model["_id"] if model else None

        return (
            jsonify(
                {
                    "message": "Login Successful",
                    "model_id": str(model_id),
                    "user-id": token,
                    "username": user["username"],
                    "license_type": user.get("license_type"),
                    "license_key": user.get("license_key"),
                    "license_start": str(user.get("license_start")),
                    "license_end": str(user.get("license_end")),
                    "license_status": license_status
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Request Reset Password API
@app.route("/request-reset-password", methods=["POST"])
def request_reset_password():
    try:
        username = request.form.get("username")

        if not username:
            return jsonify({"error": "Username is required"}), 400

        user = db.accounts.find_one({"username": username})
        if user:
            reset_token = str(uuid.uuid4())
            db.accounts.update_one(
                {"username": username},
                {"$set": {"reset_token": reset_token}}
            )
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

# Reset Password API
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
                {"$set": {"password": hashed_password}, "$unset": {"reset_token": ""}},
            )
            return jsonify({"message": "Password has been reset successfully!"}), 200
        else:
            return jsonify({"error": "Invalid or expired reset token"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
