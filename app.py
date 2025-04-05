import os
import traceback
import shutil  # For deleting temporary files
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from deepface import DeepFace

# --- Configuration ---
# Disable GPU usage for TensorFlow (optional, good for consistency)
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here' # Change this!
UPLOAD_FOLDER = 'user_images'
CREDENTIALS_FILE = 'users.txt' # File to store credentials
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Initialization ---
# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Helper Functions ---

def load_users():
    """Loads user credentials (email:hashed_password) from the file."""
    users = {}
    if not os.path.exists(CREDENTIALS_FILE):
        return users # Return empty dict if file doesn't exist
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    email, hashed_password = line.split(':', 1)
                    users[email] = hashed_password
    except Exception as e:
        print(f"Error loading users file: {e}") # Log error
    return users

def save_user(email, hashed_password):
    """Appends a new user (email:hashed_password) to the file."""
    try:
        with open(CREDENTIALS_FILE, 'a') as f:
            f.write(f"{email}:{hashed_password}\n")
        return True
    except Exception as e:
        print(f"Error saving user to file: {e}") # Log error
        return False

# --- Routes ---

@app.route('/')
def index():
    # Redirect to login page by default
    return redirect(url_for('login'))

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

        users = load_users()
        if email in users:
            return jsonify({'success': False, 'message': 'Email already registered.'})
        else:
            # Email is available
            return jsonify({'success': True})
    except Exception as e:
        print(f"Error in /check-registration: {e}")
        return jsonify({'success': False, 'message': 'Server error during check.'}), 500


@app.route('/register', methods=['POST'])
def register():
    """Handles the final registration form submission (with photo)."""
    email = request.form.get('email')
    password = request.form.get('password')
    # confirm_password = request.form.get('confirmPassword') # Already checked client-side
    photo = request.files.get('photo')

    # --- Server-side Validation ---
    if not email or not password or not photo:
        flash('Missing required fields.', 'danger')
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

        # Save credentials
        if not save_user(email, hashed_password):
             flash('Failed to save user credentials. Please try again.', 'danger')
             return redirect(url_for('register_page'))

        # Save the photo, named after the email
        filename = secure_filename(email + '.jpg')
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        print(f"Saving registration photo to: {file_path}")
        photo.save(file_path)

        # Verify the saved photo can be processed (optional but good practice)
        try:
             DeepFace.extract_faces(file_path, enforce_detection=True) # Use enforce_detection here
             print("Registered image face extraction successful")
        except ValueError as ve: # Catch specific DeepFace error for no face found
             print(f"Error processing registered image: {str(ve)}")
             # Cleanup: Remove user from file and delete photo if face not detected
             # (More robust cleanup needed for production)
             os.remove(file_path)
             # Code to remove the user line from users.txt would go here
             flash("Could not detect a face in the registered photo. Please try registering again.", 'danger')
             return redirect(url_for('register_page'))
        except Exception as e:
             print(f"Unexpected error processing registered image: {e}")
             # Cleanup as above
             flash("An error occurred processing your photo. Please try registering again.", 'danger')
             return redirect(url_for('register_page'))


        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('login_page')) # Redirect to GET route

    except Exception as e:
        print(f"Error during registration: {traceback.format_exc()}")
        flash('An error occurred during registration. Please try again.', 'danger')
        return redirect(url_for('register_page'))

# --- Login ---

@app.route('/login', methods=['GET'])
def login_page():
    """Serves the login page."""
    return render_template('login.html')

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

        hashed_password = users[email]
        if check_password_hash(hashed_password, password):
            # Credentials are valid
            return jsonify({'success': True})
        else:
            # Invalid password
            return jsonify({'success': False, 'message': 'Invalid password.'})

    except Exception as e:
        print(f"Error in /validate-credentials: {e}")
        return jsonify({'success': False, 'message': 'Server error during validation.'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Handles the final login form submission (with photo)."""
    email = request.form.get('email')
    photo = request.files.get('photo')
    temp_filename = 'temp_login.jpg' # Use a distinct temp name

    # --- Server-side Validation ---
    if not email or not photo:
        flash('Missing email or photo.', 'danger')
        return redirect(url_for('login_page'))

    # --- Verify User Exists (Credential check happened via AJAX) ---
    registered_img_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(email + '.jpg'))

    if not os.path.exists(registered_img_path):
        # This case should ideally be caught earlier, but double-check
        flash("Registered user data not found. Please register or contact support.", 'danger')
        return redirect(url_for('register_page')) # Go to register if image missing

    # --- Process Login Photo ---
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    cleanup_temp = False # Flag to ensure temp file is deleted

    try:
        photo.save(temp_path)
        cleanup_temp = True # Mark that file needs cleanup

        print(f"Attempting verification: Login photo ({temp_path}) vs Registered ({registered_img_path})")
        # Optional: Check file sizes for basic sanity check
        # print(f"File sizes - Temp: {os.path.getsize(temp_path)} bytes, Registered: {os.path.getsize(registered_img_path)} bytes")

        # --- DeepFace Verification ---
        # Consider trying different models/backends if default fails
        result = DeepFace.verify(
            img1_path=temp_path,
            img2_path=registered_img_path,
            model_name='VGG-Face', # Example: Try different models ('Facenet', 'ArcFace')
            detector_backend='opencv', # Options: 'opencv', 'ssd', 'dlib', 'mtcnn', 'retinaface'
            enforce_detection=False # Be lenient first, maybe try True if needed
        )
        print(f"DeepFace Verification Result: {result}") # Log the full result

        if result['verified']:
            session['user'] = email # Store email in session on successful login
            flash("Login successful! Welcome.", 'success')
            return redirect(url_for('home'))
        else:
            flash("Face doesn't match. Access denied.", 'danger')
            return redirect(url_for('login_page'))

    except ValueError as ve: # Catch specific DeepFace error (e.g., face not found)
         print(f"ValueError during face verification: {str(ve)}")
         flash("Could not detect a face in one of the photos. Please try again.", 'danger')
         return redirect(url_for('login_page'))
    except Exception as e:
        print(f"Error during face verification: {traceback.format_exc()}")
        flash("An error occurred during face verification. Please try again.", 'danger')
        return redirect(url_for('login_page'))
    finally:
        # --- Cleanup ---
        if cleanup_temp and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                print(f"Removed temporary file: {temp_path}")
            except Exception as e:
                print(f"Error removing temporary file {temp_path}: {e}")


# --- Home & Logout ---

@app.route('/home')
def home():
    """Displays the user's home page."""
    if 'user' not in session:
        flash("Please login first.", 'warning')
        return redirect(url_for('login_page'))
    user_email = session['user']
    return render_template('home.html', email=user_email)


@app.route('/logout', methods=['GET']) # Use GET for simple logout link/button
def logout():
    """Logs the user out."""
    session.pop('user', None) # Clear specific session key
    # session.clear() # Or clear the entire session
    flash("Logged out successfully.", 'info')
    return redirect(url_for('login_page'))

# --- Run Application ---
if __name__ == '__main__':
    print("Starting Flask app...")
    # Note: debug=True reloads on code changes but can cause issues
    # with some libraries or background tasks. Set to False for production.
    app.run(debug=True, host='0.0.0.0', port=5000) # Make accessible on network if needed