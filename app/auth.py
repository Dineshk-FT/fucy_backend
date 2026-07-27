from flask import current_app, request, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from db import db
import uuid
from datetime import datetime, timedelta
from bson import ObjectId
import random
from app.__init__ import send_email
import os
import stripe
from flask_mail import Mail, Message
import secrets
import string
from functools import wraps # <--- ADDED THIS IMPORT
from app.Methods.auth_helpers import get_user_id, create_token, get_token_error

# Initialize Flask-Mail in your app
mail = Mail()

from dotenv import load_dotenv
load_dotenv()
stripe_key = os.getenv('STRIPE_SECRET_KEY')
stripe.api_key = stripe_key

def generate_license_key():
    """Generate a unique license key in the format: XXXX-XXXX-XXXX-XXXX""" 
    chars = string.ascii_uppercase + string.digits
    while True:
        key = '-'.join(
            ''.join(random.choices(chars, k=4)) 
            for _ in range(4)
        )
        if not db.accounts.find_one({"license_key": key}):
            return key


# ==========================================
# THE AUTHORIZATION DECORATOR
# Import this into your other files!
# ==========================================
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Grab the token from the Authorization: Bearer <token> header
        user_id = get_user_id()

        # 2. Check if it's missing/expired/invalid, with a specific reason
        #    so the frontend can tell an expired session apart from a bad one.
        if not user_id:
            reason = get_token_error()
            if reason == "expired":
                return jsonify({"error": "Unauthorized: token has expired", "reason": "token_expired"}), 401
            if reason == "missing":
                return jsonify({"error": "Unauthorized: Bearer token is required", "reason": "token_missing"}), 401
            return jsonify({"error": "Unauthorized: invalid token", "reason": "token_invalid"}), 401
            
        try:
            # 3. Validate user exists
            user = db.accounts.find_one({"_id": ObjectId(user_id)})
            if not user:
                return jsonify({"error": "Unauthorized: No such user found"}), 401
        except Exception:
            # Catches errors if the user-id isn't a valid 24-character ObjectId
            return jsonify({"error": "Unauthorized: Invalid user-id format"}), 401
            
        # 4. If everything is good, proceed to the actual route function
        return f(*args, **kwargs)
        
    return decorated_function

# ==========================================


auth = Blueprint("auth", __name__)

@auth.route("/", methods=["GET"])
def hello():
    return "WORKING SUCCESSFULLY"

@auth.route("/verify-card", methods=["POST"])
def verify_card():
    try:
        if request.is_json:
            data = request.get_json()
            payment_method_id = data.get('payment_method_id')
        else:
            payment_method_id = request.form.get('payment_method_id')
            
        if not payment_method_id:
            return jsonify({"error": "Payment method ID is required"}), 400
        
        try:
            if not stripe_key:
                raise ValueError("Stripe API key is not configured")
                
            payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
            
            if payment_method.type == 'card':
                return jsonify({
                    "success": True, 
                    "message": "Card verified successfully",
                    "card": {
                        "last4": payment_method.card.last4,
                        "brand": payment_method.card.brand,
                        "exp_month": payment_method.card.exp_month,
                        "exp_year": payment_method.card.exp_year
                    }
                }), 200
            else:
                return jsonify({"error": "Invalid payment method type"}), 400
                
        except stripe.error.CardError as e:
            current_app.logger.error(f"Card verification failed: {str(e)}")
            return jsonify({"error": f"Card verification failed: {e.user_message if hasattr(e, 'user_message') else str(e)}"}), 400
            
        except stripe.error.StripeError as e:
            current_app.logger.error(f"Stripe API error: {str(e)}")
            return jsonify({"error": "An error occurred while processing your payment. Please try again."}), 500
            
    except Exception as e:
        current_app.logger.error(f"Unexpected error in verify_card: {str(e)}")
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

@auth.route("/register", methods=["POST"])
def register():
    try:
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        org = request.form.get("org")
        password = request.form.get("password")
        license_type = request.form.get("license_type")
        role = request.form.get("role")
        email = request.form.get("email")
        payment_method_id = request.form.get("payment_method_id")

        if not all([firstname, lastname, org, password, role, email]):
            return jsonify({"error": "All fields (firstname, lastname, org, password, role, email) are required"}), 400

        if license_type != "trial":
            if not payment_method_id:
                return jsonify({"error": "Payment method ID is required for non-trial plans"}), 400
            try:
                payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
                if payment_method.type != 'card':
                    return jsonify({"error": "Invalid payment method type"}), 400
            except stripe.error.CardError as e:
                return jsonify({"error": f"Card verification failed: {str(e)}"}), 400
            except stripe.error.StripeError as e:
                return jsonify({"error": f"Stripe error: {str(e)}"}), 500

        username = f"{firstname}.{lastname}".lower()
        existing_user = db.accounts.find_one({"username": username})
        existing_org = db.accounts.find_one({"org": org})

        if existing_user and existing_org:
            return jsonify({"error": "Username and organization combination already exists"}), 400

        duration_mapping = {
            "trial": 14,
            "1month": 30,
            "3months": 90,
            "6months": 180,
            "1year": 365
        }

        if license_type not in duration_mapping:
            return jsonify({"error": "Invalid license type"}), 400

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=duration_mapping[license_type])
        license_key = generate_license_key()

        db.accounts.insert_one({
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "email": email,
            "org": org,
            "password": hashed_password,
            "role": role,
            "license_type": license_type,
            "license_key": license_key,
            "license_start": start_date,
            "license_end": end_date,
            "payment_method_id": payment_method_id if license_type != "trial" else None
        })

        email_subject = "🎉 Welcome to FUCY TECH - Your License Key"
        email_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #4a6fa5;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    padding: 20px;
                    border: 1px solid #e0e0e0;
                    border-top: none;
                    border-radius: 0 0 5px 5px;
                }}
                .license-box {{
                    background-color: #f8f9fa;
                    border-left: 4px solid #4a6fa5;
                    padding: 15px;
                    margin: 20px 0;
                    font-family: monospace;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #e0e0e0;
                    font-size: 0.9em;
                    color: #666666;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Welcome to FUCY TECH!</h2>
            </div>
            <div class="content">
                <p>Dear {firstname} {lastname},</p>
                <p>Thank you for registering with FUCY TECH! We're excited to have you on board.</p>
                <div class="license-box">
                    <p><strong>Your License Key:</strong><br>
                    <span style="font-size: 1.2em; font-weight: bold; color: #2c3e50;">{license_key}</span></p>
                    <p><strong>License Type:</strong> {license_type}<br>
                    <strong>Valid Until:</strong> {end_date.strftime('%B %d, %Y')}</p>
                </div>
                <p>Please keep this license key safe, as it will be required to access your account and our services.</p>
                <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                <div class="footer">
                    <p>Best regards,<br>
                    <strong>The FUCY TECH Team</strong></p>
                    <p style="font-size: 0.8em; margin-top: 20px; color: #999999;">
                        This is an automated message, please do not reply directly to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        try:
            send_email(email, email_subject, email_body, is_html=True)
        except Exception as e:
            current_app.logger.error(f"Failed to send email: {str(e)}")

        return jsonify({
            "message": f"User registered successfully with {license_type} license!",
            "license_key": license_key
        }), 201
    except Exception as e:
        current_app.logger.error(f"Error in register: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/check-user-status", methods=["POST"])
def check_user_status():
    try:
        email = request.form.get("email")
        org = request.form.get("org")
        
        if not email or not org:
            return jsonify({"error": "Email and Organization are required"}), 400
            
        # 1. Fetch the user from the database first
        user_with_email = db.accounts.find_one({
            "$or": [{"email": email}, {"username": email}]
        })
        
        if not user_with_email:
            return jsonify({"exists": False, "message": f'User not found in the organization {org}'}), 200
            
        # 2. Check if the database record indicates the user is an admin
        if user_with_email.get("user_type") == "admin":
            return jsonify({"exists": True, "message": f'User found in the organization {org}'}), 200

        # 3. For non-admins, proceed with the organization-specific check
        user = db.accounts.find_one({"email": email, "org": org})
        
        if not user:
            return jsonify({"exists": False, "message": f'User not found in the organization {org}'}), 200
            
        license_end = user.get("license_end")
        trialUsed = user.get("license_type") == "trial"
        trialExpired = trialUsed and license_end and license_end < datetime.utcnow()
        
        return jsonify({
            "exists": True,
            "trialUsed": trialUsed,
            "trialExpired": trialExpired,
            "license_end": license_end.isoformat() if license_end else None,
            "message": "Valid trial license" if trialUsed else "Valid user with no trial license"
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error in check_user_status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/send-verification-otp", methods=["POST"])
def send_verification_otp():
    try:
        email = request.form.get("email")
        if not email:
            return jsonify({"error": "Email is required"}), 400
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
        current_app.logger.error(f"Error in send_verification_otp: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/verify-otp", methods=["POST"])
def verify_otp():
    try:
        email = request.form.get("email")
        otp = request.form.get("otp")
        if not email or not otp:
            return jsonify({"error": "Email and OTP required"}), 400
        record = db.verification.find_one({"email": email, "otp": otp})
        if not record:
            return jsonify({"error": "Invalid OTP"}), 400
        if record["expires_at"] < datetime.utcnow():
            return jsonify({"error": "OTP expired"}), 400
        db.verification.delete_one({"_id": record["_id"]})
        return jsonify({"message": "Email verified"}), 200
    except Exception as e:
        current_app.logger.error(f"Error in verify_otp: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/upgrade-license", methods=["POST"])
# Note: You COULD put @require_auth here if you want to force them to be logged in to upgrade!
def upgrade_license():
    try:
        user_id = request.form.get("user_id")
        license_type = request.form.get("license_type")
        payment_method_id = request.form.get("payment_method_id")
        if not user_id or not license_type:
            return jsonify({"error": "User ID and license type are required"}), 400
        if payment_method_id:
            try:
                payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
                if payment_method.type != 'card':
                    return jsonify({"error": "Invalid payment method type"}), 400
            except stripe.error.CardError as e:
                return jsonify({"error": f"Card verification failed: {str(e)}"}), 400
            except stripe.error.StripeError as e:
                return jsonify({"error": f"Stripe error: {str(e)}"}), 500
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
        update_data = {
            "license_type": license_type,
            "license_start": start_date,
            "license_end": end_date
        }
        if payment_method_id:
            update_data["payment_method_id"] = payment_method_id
        db.accounts.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        return jsonify({"message": f"License upgraded to {license_type}"}), 200
    except Exception as e:
        current_app.logger.error(f"Error in upgrade_license: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        user = db.accounts.find_one({
            "$or": [{"username": username}, {"email": username}]
        })
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid username or password"}), 401
        user_type = user.get("user_type")
        organization = user.get("org", "")
        license_end = user.get("license_end")
        current_date = datetime.utcnow()
        is_admin = user_type == "admin"
        license_status = "active"
        if not is_admin:
            if not license_end:
                license_status = "inactive"
            elif current_date > license_end:
                license_status = "expired"
        if not is_admin:
            if license_status in ["inactive", "expired"] and not organization:
                return jsonify({
                    "error": "Access denied. No valid license and no organization assigned.",
                    "license_status": license_status
                }), 403
        if license_status in ["inactive", "expired"] and not is_admin:
            return jsonify({
                "error": "License expired. Please upgrade to continue.",
                "license_status": license_status
            }), 403
        token = create_token(user["_id"])
        model = db.Models.find_one(
            {"user_id": str(user["_id"]), "status": 1},
            sort=[("_id", -1)]
        )
        model_id = model["_id"] if model else None
        return jsonify({
            "message": "Login Successful",
            "model_id": str(model_id),
            "org":user.get("org"),
            "token": token,
            "user-id": str(user["_id"]),  # kept for backward compatibility; use "token" as the Bearer token going forward
            "username": user["username"],
            "license_type": user.get("license_type"),
            "license_key": user.get("license_key"),
            "license_start": str(user.get("license_start")),
            "license_end": str(user.get("license_end")),
            "license_status": license_status
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error in login: {str(e)}")
        return jsonify({"error": str(e)}), 500


@auth.route("/request-reset-password", methods=["POST"])
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
            return jsonify({
                "message": "Password reset requested. Check your email for the reset link.",
                "reset_token": reset_token
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        current_app.logger.error(f"Error in request_reset_password: {str(e)}")
        return jsonify({"error": str(e)}), 500

@auth.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        email = request.form.get("email")
        org = request.form.get("org")
        
        if not email or not org:
            return jsonify({"error": "Email and organization are required"}), 400
        
        alphabet = string.ascii_letters + string.digits
        random_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        hashed_password = generate_password_hash(random_password, method="pbkdf2:sha256")
        
        result = db.accounts.update_one(
            {"email": email, "org": org},
            {"$set": {"password": hashed_password}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "User not found with provided email and organization"}), 400
        
        try:
            msg = Message(
                subject="🔒 Your Password Has Been Reset",
                sender="noreply@yourapp.com",
                recipients=[email]
            )
            
            msg.html = f"""
            <div style="font-family: Arial, sans-serif; color: #333; padding: 20px;">
                <div style="max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); background-color: #fafafa;">
                    <div style="background-color: #4CAF50; color: white; padding: 15px 20px; border-radius: 10px 10px 0 0;">
                        <h2 style="margin: 0;">YourApp Password Reset</h2>
                    </div>
                    <div style="padding: 20px;">
                        <p>Hello,</p>
                        <p>Your password has been <strong>successfully reset</strong> for your organization:</p>
                        
                        <p style="margin: 10px 0; font-size: 16px;">
                            <b>Organization:</b> {org}<br>
                            <b>New Password:</b> 
                            <span style="display: inline-block; background-color: #eee; padding: 6px 12px; border-radius: 6px; font-family: monospace; color: #2c3e50;">
                                {random_password}
                            </span>
                        </p>

                        <p>Please <a href="https://yourapp.com/login" style="color: #4CAF50; text-decoration: none;">log in</a> and change your password immediately for security.</p>

                        <p style="margin-top: 30px;">Best regards,<br><b>YourApp Team</b></p>
                    </div>
                </div>
            </div>
            """
            
            mail.send(msg)
            
        except Exception as email_error:
            current_app.logger.error(f"Error sending email: {str(email_error)}")
            return jsonify({"error": "Password was reset but failed to send email"}), 500
        
        return jsonify({"message": "New password has been sent to your email"}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error in forgot_password: {str(e)}")
        return jsonify({"error": str(e)}), 500
  

@auth.route("/reset-password", methods=["POST"])
# Note: Depending on your frontend flow, you might actually want to protect 
# this specific route with @require_auth if they change passwords from inside the app!
def reset_password():
    try:
        identifier = request.form.get("identifier") 
        org = request.form.get("org")
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        
        if not all([identifier, org, old_password, new_password]):
            return jsonify({"error": "All fields are required"}), 400
        
        if len(new_password) < 8:
            return jsonify({"error": "New password must be at least 8 characters long"}), 400
        
        user = db.accounts.find_one({
            "$or": [
                {"email": identifier},
                {"username": identifier}
            ],
            "org": org
        })
        
        if not user:
            return jsonify({"error": "User not found with provided credentials"}), 400
        
        if not check_password_hash(user["password"], old_password):
            return jsonify({"error": "Current password is incorrect"}), 400
        
        hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
        
        result = db.accounts.update_one(
            {"_id": user["_id"]},
            {"$set": {"password": hashed_password}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update password"}), 500
        
        return jsonify({"message": "Password has been reset successfully"}), 200
        
    except Exception as e:
        current_app.logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500