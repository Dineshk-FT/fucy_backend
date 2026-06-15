import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import request, jsonify, Blueprint
import os

app = Blueprint("contact", __name__)
PASSWORD = os.environ.get("GOOGLE_APP_PASSWORD")  # Ensure this is set in your environment variables
# ==============================================================================
# SERVER CONFIGURATION
# Consider moving these to environment variables (e.g., os.environ.get) for production.
# ==============================================================================
SERVER_BOT_EMAIL = "fucytech.inquiries@gmail.com" 
SERVER_BOT_PASSWORD = PASSWORD
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
RECEIVER_EMAIL = "info@fucytech.com"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def generate_html_template(data):
    """Generates a styled HTML email template."""
    return f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
          
          <!-- Header -->
          <div style="background-color: #1976d2; color: #ffffff; padding: 20px; text-align: center;">
            <h2 style="margin: 0; font-size: 24px;">New Inquiry Received</h2>
            <p style="margin: 5px 0 0; font-size: 14px; opacity: 0.9;">Fucy Tech Website Form</p>
          </div>

          <!-- Content -->
          <div style="padding: 30px;">
            <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
              You have received a new message from the contact form. Here are the details:
            </p>

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; width: 35%; font-weight: bold; color: #555555;">Name:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #222222;">{data['name']}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Company:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #222222;">{data['companyName']}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Email:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #1976d2;">
                  <a href="mailto:{data['email']}" style="color: #1976d2; text-decoration: none;">{data['email']}</a>
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Source:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #222222;">{data['hearAboutUs']}</td>
              </tr>
            </table>

            <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #1976d2; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #555555;">Message:</h4>
              <p style="margin: 0; color: #333333; line-height: 1.6; white-space: pre-wrap;">{data.get('message', 'No message provided.')}</p>
            </div>
          </div>

          <!-- Footer -->
          <div style="background-color: #eeeeee; color: #777777; text-align: center; padding: 15px; font-size: 12px;">
            <p style="margin: 0;">This is an automated notification from your backend.</p>
          </div>

        </div>
      </body>
    </html>
    """

def send_email_notification(data):
    """Handles the SMTP connection and payload delivery."""
    msg = MIMEMultipart('alternative')
    msg['From'] = SERVER_BOT_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = f"New Inquiry: {data['name']} from {data['companyName']}"

    # Attach the HTML content
    html_content = generate_html_template(data)
    msg.attach(MIMEText(html_content, 'html'))

    # Connect to server and send
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls() 
        server.login(SERVER_BOT_EMAIL, SERVER_BOT_PASSWORD)
        server.send_message(msg)

# ==============================================================================
# WORK SUBMISSION HELPER FUNCTIONS
# ==============================================================================
def generate_work_html_template(data):
    """Generates a styled HTML email template for Work Submissions."""
    return f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
          
          <!-- Header -->
          <div style="background-color: #2e7d32; color: #ffffff; padding: 20px; text-align: center;">
            <h2 style="margin: 0; font-size: 24px;">New Work Submission</h2>
            <p style="margin: 5px 0 0; font-size: 14px; opacity: 0.9;">Fucy Tech Website Form</p>
          </div>

          <!-- Content -->
          <div style="padding: 30px;">
            <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
              A user has submitted a new project or work idea. Here are the details:
            </p>

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; width: 35%; font-weight: bold; color: #555555;">Name:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #222222;">{data.get('name', 'N/A')}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Email:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #1976d2;">
                  <a href="mailto:{data.get('email', '')}" style="color: #1976d2; text-decoration: none;">{data.get('email', 'N/A')}</a>
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Project Title:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #222222;">{data.get('projectTitle', 'N/A')}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; font-weight: bold; color: #555555;">Work Link:</td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; color: #1976d2;">
                  <a href="{data.get('workLink', '#')}" target="_blank" style="color: #1976d2; text-decoration: none;">{data.get('workLink', 'N/A')}</a>
                </td>
              </tr>
            </table>

            <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #2e7d32; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #555555;">Project Description:</h4>
              <p style="margin: 0; color: #333333; line-height: 1.6; white-space: pre-wrap;">{data.get('projectDescription', 'No description provided.')}</p>
            </div>
          </div>

          <!-- Footer -->
          <div style="background-color: #eeeeee; color: #777777; text-align: center; padding: 15px; font-size: 12px;">
            <p style="margin: 0;">This is an automated notification from your backend.</p>
          </div>

        </div>
      </body>
    </html>
    """

def send_work_notification(data):
    """Handles the SMTP connection for work submissions."""
    msg = MIMEMultipart('alternative')
    msg['From'] = SERVER_BOT_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = f"New Work Submission: {data.get('projectTitle', 'Untitled')} from {data.get('name')}"

    # Attach the HTML content
    html_content = generate_work_html_template(data)
    msg.attach(MIMEText(html_content, 'html'))

    # Connect to server and send
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls() 
        server.login(SERVER_BOT_EMAIL, SERVER_BOT_PASSWORD)
        server.send_message(msg)


# ==============================================================================
# CONTACT ROUTE
# ==============================================================================
@app.route('/v1/contact', methods=['POST'])
def handle_contact_form():
    try:
        # CHANGE HERE: Use get_json() to read application/json data
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'companyName', 'email', 'hearAboutUs', 'message']
        if not all(data.get(field) for field in required_fields):
            return jsonify({
                "status": "error",
                "message": "Missing required fields."
            }), 400

        # Trigger email send
        send_email_notification(data)

        return jsonify({
            "status": "success",
            "message": "Thank you for contacting Fucy Tech! We will get back to you soon."
        }), 200

    except smtplib.SMTPAuthenticationError:
        print("CRITICAL: SMTP Authentication failed. Check your bot email and App Password.")
        return jsonify({"status": "error", "message": "Email delivery configuration failed."}), 500
    except Exception as e:
        print(f"ERROR processing contact request: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500
    

# ==============================================================================
# WORK SUBMISSION ROUTE
# ==============================================================================
@app.route('/v1/work', methods=['POST'])
def handle_work_form():
    try:
        data = request.get_json()
        
        # Validate required fields (Name, Email, and Description)
        required_fields = ['name', 'email', 'projectDescription']
        if not all(data.get(field) for field in required_fields):
            return jsonify({
                "status": "error",
                "message": "Missing required fields. Name, Email, and Project Description are required."
            }), 400

        # Trigger email send
        send_work_notification(data)

        return jsonify({
            "status": "success",
            "message": "Your work has been successfully submitted to Fucy Tech!"
        }), 200

    except smtplib.SMTPAuthenticationError:
        print("CRITICAL: SMTP Authentication failed. Check your bot email and App Password.")
        return jsonify({"status": "error", "message": "Email delivery configuration failed."}), 500
    except Exception as e:
        print(f"ERROR processing work request: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500
    