import os
import traceback
import shutil
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from deepface import DeepFace
import logging # Import logging

# --- Configuration ---
# Disable GPU usage for TensorFlow (optional, good for consistency)
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
# IMPORTANT: Change this secret key! Use a long, random string.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', '8f42a73054b1749f8f58848be5e6502c')
UPLOAD_FOLDER = 'user_images'
CREDENTIALS_FILE = 'users.txt' # File to store credentials (username:email:hashed_password)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Initialization ---
# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Helper Functions ---

def load_users():
    """
    Loads user credentials from the file.
    Returns a dictionary: {email: {'username': username, 'password': hashed_password}}
    """
    users = {}
    if not os.path.exists(CREDENTIALS_FILE):
        return users # Return empty dict if file doesn't exist
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line: # Skip empty lines
                    continue
                parts = line.split(':', 2) # Split into max 3 parts
                if len(parts) == 3:
                    username, email, hashed_password = parts
                    users[email] = {'username': username, 'password': hashed_password}
                else:
                     logging.warning(f"Skipping malformed line {i+1} in {CREDENTIALS_FILE}")
    except Exception as e:
        logging.error(f"Error loading users file: {e}", exc_info=True) # Log error with traceback
    return users

def save_user(username, email, hashed_password):
    """Appends a new user (username:email:hashed_password) to the file."""
    try:
        with open(CREDENTIALS_FILE, 'a') as f:
            f.write(f"{username}:{email}:{hashed_password}\n")
        logging.info(f"Saved user: {username} ({email})")
        return True
    except Exception as e:
        logging.error(f"Error saving user to file: {e}", exc_info=True) # Log error
        return False

# --- Routes ---

@app.route('/')
def index():
    # Redirect to login page by default
    return redirect(url_for('login_page'))

# --- Registration ---

@app.route('/register', methods=['GET'])
def register_page():
    """Serves the registration page."""
    return render_template('register.html')

@app.route('/check-registration', methods=['POST'])
def check_registration():
    """
    AJAX endpoint for register.html.
    Checks if email exists before proceeding to camera.
    """
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required.'}), 400

        # Basic email format check server-side
        if '@' not in email or '.' not in email.split('@')[-1]:
             return jsonify({'success': False, 'message': 'Invalid email format.'}), 400

        users = load_users()
        if email in users:
            return jsonify({'success': False, 'message': 'Email already registered.'})
        else:
            # Email is available
            return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error in /check-registration: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Server error during check.'}), 500


@app.route('/register', methods=['POST'])
def register():
    """Handles the final registration form submission (with photo)."""
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    photo = request.files.get('photo')

    # --- Server-side Validation ---
    if not username or not email or not password or not photo:
        flash('Missing required fields (Username, Email, Password, Photo).', 'danger')
        return redirect(url_for('register_page'))

    # Re-check email availability server-side (important security measure)
    users = load_users()
    if email in users:
        flash('Email already registered. Please login or use a different email.', 'warning')
        return redirect(url_for('register_page'))

    # --- Process Registration ---
    try:
        # Hash the password
        hashed_password = generate_password_hash(password)

        # Save credentials (username, email, hashed_password)
        if not save_user(username, email, hashed_password):
             flash('Failed to save user credentials. Please try again.', 'danger')
             return redirect(url_for('register_page'))

        # Save the photo, named after the email (ensure filename safety)
        # Use email for image filename for consistency with login lookup
        safe_email_filename = secure_filename(email).replace('@', '_').replace('.', '_')
        filename = safe_email_filename + '.jpg'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        logging.info(f"Saving registration photo to: {file_path}")
        photo.save(file_path)

        # Verify the saved photo can be processed (optional but good practice)
        try:
             # Perform a quick face detection check on the registered image
             faces = DeepFace.extract_faces(file_path, detector_backend='opencv', enforce_detection=True)
             if not faces: # Check if the list of faces is empty
                 raise ValueError("No face detected in the image.")
             logging.info(f"Registered image face extraction successful for {email}")
        except ValueError as ve: # Catch specific DeepFace error for no face found or other issues
             logging.warning(f"Face detection failed for registered image {file_path}: {str(ve)}")
             # Cleanup: Remove user from file and delete photo if face not detected
             # Note: Removing from file is complex, needs reading/writing the whole file.
             # For simplicity here, we just delete the photo and flash an error.
             # A better approach involves database transactions or more robust file handling.
             if os.path.exists(file_path):
                 os.remove(file_path)
             # Attempt to remove user from file (simplified, might leave empty lines)
             try:
                 with open(CREDENTIALS_FILE, "r") as f:
                     lines = f.readlines()
                 with open(CREDENTIALS_FILE, "w") as f:
                     for line in lines:
                         if not line.strip().endswith(f":{hashed_password}"): # Be careful with this check
                             f.write(line)
             except Exception as file_e:
                 logging.error(f"Could not remove user {email} from file during cleanup: {file_e}")

             flash("Registration failed: Could not detect a clear face in the photo. Please try again with a well-lit, front-facing picture.", 'danger')
             return redirect(url_for('register_page'))
        except Exception as e:
             logging.error(f"Unexpected error processing registered image {file_path}: {e}", exc_info=True)
             # Cleanup as above
             if os.path.exists(file_path):
                 os.remove(file_path)
             # Attempt removal from file
             # ... (similar file removal logic as above) ...
             flash("An error occurred processing your photo. Please try registering again.", 'danger')
             return redirect(url_for('register_page'))

        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('login_page')) # Redirect to GET route

    except Exception as e:
        logging.error(f"Error during registration: {e}", exc_info=True)
        flash('An error occurred during registration. Please try again.', 'danger')
        return redirect(url_for('register_page'))

# --- Login ---

@app.route('/login', methods=['GET'])
def login_page():
    """Serves the login page."""
    # Pass potential alert info from failed POST attempt
    security_alert = request.args.get('security_alert', 'false').lower() == 'true'
    alert_email = request.args.get('alert_email', None)
    error_message = request.args.get('error_message', None)
    if error_message:
        flash(error_message, 'danger') # Flash message if provided

    return render_template('login.html', security_alert=security_alert, alert_email=alert_email)


@app.route('/validate-credentials', methods=['POST'])
def validate_credentials():
    """
    AJAX endpoint for login.html.
    Validates email and password before proceeding to camera.
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required.'}), 400

        users = load_users()
        if email not in users:
            return jsonify({'success': False, 'message': 'Email not found. Please register.'})

        # Check password using the loaded user data structure
        user_data = users[email]
        hashed_password = user_data['password']
        if check_password_hash(hashed_password, password):
            # Credentials are valid
            logging.info(f"Credentials validated successfully for {email}")
            return jsonify({'success': True})
        else:
            # Invalid password
            logging.warning(f"Invalid password attempt for {email}")
            return jsonify({'success': False, 'message': 'Invalid password.'})

    except Exception as e:
        logging.error(f"Error in /validate-credentials: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Server error during validation.'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Handles the final login form submission (with photo)."""
    email = request.form.get('email')
    photo = request.files.get('photo')
    # Use a unique temp name to avoid clashes if multiple logins happen
    temp_filename = f'temp_login_{os.urandom(4).hex()}.jpg'
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    cleanup_temp = False # Flag to ensure temp file is deleted

    # --- Server-side Validation ---
    if not email or not photo:
        flash('Missing email or photo.', 'danger')
        return redirect(url_for('login_page'))

    # --- Verify User Exists and Get Registered Image Path ---
    users = load_users()
    if email not in users:
        flash('Email not registered.', 'danger')
        return redirect(url_for('register_page')) # Go to register if email missing

    # Construct the path to the registered image (using the same safe naming as registration)
    safe_email_filename = secure_filename(email).replace('@', '_').replace('.', '_')
    registered_img_filename = safe_email_filename + '.jpg'
    registered_img_path = os.path.join(app.config['UPLOAD_FOLDER'], registered_img_filename)

    if not os.path.exists(registered_img_path):
        logging.error(f"Registered image not found for {email} at {registered_img_path}")
        flash("Registered user photo not found. Please re-register or contact support.", 'danger')
        # Consider invalidating the user entry in users.txt here if desired
        return redirect(url_for('register_page'))

    # --- Process Login Photo ---
    try:
        photo.save(temp_path)
        cleanup_temp = True # Mark that file needs cleanup
        logging.info(f"Login attempt for {email}. Saved temp photo: {temp_path}")

        # --- DeepFace Verification ---
        logging.info(f"Attempting verification: Login photo ({temp_path}) vs Registered ({registered_img_path})")
        result = DeepFace.verify(
            img1_path=temp_path,
            img2_path=registered_img_path,
            model_name='VGG-Face', # Or 'Facenet512', 'ArcFace'
            detector_backend='opencv', # Or 'mtcnn', 'retinaface'
            enforce_detection=True # Crucial for security - ensure faces are found in *both*
        )
        logging.info(f"DeepFace Verification Result for {email}: {result}") # Log the full result

        if result['verified']:
            user_data = users[email]
            username = user_data['username']
            session['user_email'] = email # Store email in session
            session['user_name'] = username # Store username in session
            logging.info(f"Login successful for {username} ({email})")
            flash(f"Welcome back, {username}!", 'success')
            return redirect(url_for('home'))
        else:
            # *** FACIAL VERIFICATION FAILED ***
            logging.warning(f"Facial verification FAILED for {email}. Credentials were correct.")
            # Instead of redirect, render login page again with flags for EmailJS trigger
            # Pass email and alert flag via query parameters during redirect for simplicity client side
            error_msg = "Face doesn't match. Access denied. A security alert has been sent to your email."
            # Don't flash here, pass it to be flashed on the re-rendered page
            # We redirect to the GET route to make client-side JS simpler
            return redirect(url_for('login_page', security_alert='true', alert_email=email, error_message=error_msg))

    except ValueError as ve: # Catch specific DeepFace error (e.g., face not found in one/both images)
         logging.warning(f"ValueError during face verification for {email}: {str(ve)}")
         # Check if it's a "Face could not be detected" error specifically
         if "Face could not be detected" in str(ve) or "cannot be verified" in str(ve):
             flash("Login failed: Could not clearly detect a face in the login photo or the registered photo. Please try again.", 'danger')
         else:
            flash("Login failed due to a face verification issue. Please try again.", 'danger')
         return redirect(url_for('login_page'))
    except Exception as e:
        logging.error(f"Error during face verification for {email}: {e}", exc_info=True)
        flash("An error occurred during login. Please try again.", 'danger')
        return redirect(url_for('login_page'))
    finally:
        # --- Cleanup ---
        if cleanup_temp and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logging.info(f"Removed temporary login file: {temp_path}")
            except Exception as e:
                logging.error(f"Error removing temporary file {temp_path}: {e}")


# --- Home & Logout ---

@app.route('/home')
def home():
    """Displays the user's home page."""
    # Check if user is logged in using session keys
    if 'user_email' not in session or 'user_name' not in session:
        flash("Please login first.", 'warning')
        return redirect(url_for('login_page'))

    user_email = session['user_email']
    user_name = session['user_name']
    logging.info(f"Accessing home page for {user_name} ({user_email})")
    return render_template('home.html', username=user_name, email=user_email) # Pass both just in case


@app.route('/logout', methods=['GET']) # Use GET for simple logout link/button
def logout():
    """Logs the user out."""
    # Get username before popping for logging purposes
    username = session.get('user_name', 'Unknown User')
    email = session.get('user_email', 'unknown email')

    session.pop('user_email', None) # Clear specific session key
    session.pop('user_name', None) # Clear specific session key
    # session.clear() # Or clear the entire session if preferred
    logging.info(f"User {username} ({email}) logged out.")
    flash("Logged out successfully.", 'info')
    return redirect(url_for('login_page'))

# --- Run Application ---
if __name__ == '__main__':
    logging.info("Starting Flask app...")
    # Set debug=False for production/stable testing
    # Host 0.0.0.0 makes it accessible on your network
    app.run(debug=True, host='0.0.0.0', port=5000)