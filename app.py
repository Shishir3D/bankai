import os
import traceback
from flask import Flask, render_template, request, redirect, session, url_for, flash
from deepface import DeepFace
from werkzeug.utils import secure_filename
import shutil  # For deleting temporary files

# Disable GPU usage for TensorFlow
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs

app = Flask(__name__)
app.secret_key = 'supersecret'
UPLOAD_FOLDER = 'user_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        img = request.files['photo']

        filename = secure_filename(email + '.jpg')
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Debugging: print the path to verify
        print(f"Saving registration photo to: {file_path}")

        img.save(file_path)
        flash('Registered successfully! Now login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        img = request.files['photo']

        filename = 'temp.jpg'
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        img.save(temp_path)

        registered_img_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(email + '.jpg'))

        if not os.path.exists(registered_img_path):
            flash("User not found. Please register.", 'danger')
            return redirect(url_for('register'))

        try:
            print(f"File sizes - Temp: {os.path.getsize(temp_path)} bytes, Registered: {os.path.getsize(registered_img_path)} bytes")
            
            # First verify each image individually
            try:
                DeepFace.extract_faces(temp_path)
                print("Temp image face extraction successful")
            except Exception as e:
                print(f"Error processing temp image: {str(e)}")
                flash("Could not detect a face in your photo. Please try again.", 'danger')
                return redirect(url_for('login'))

            try:
                DeepFace.extract_faces(registered_img_path)
                print("Registered image face extraction successful")
            except Exception as e:
                print(f"Error processing registered image: {str(e)}")
                flash("Could not detect a face in your registered photo. Please register again.", 'danger')
                return redirect(url_for('register'))

            # Now try verification
            result = DeepFace.verify(
                img1_path=temp_path,
                img2_path=registered_img_path,
                detector_backend='opencv',  # Try different backend
                enforce_detection=False
            )

            if result['verified']:
                session['user'] = email
                flash("Login successful! Welcome.", 'success')
                return redirect(url_for('home'))
            else:
                flash("Face doesn't match. Access denied.", 'danger')
                return redirect(url_for('login'))

        except Exception as e:
            print(f"Full error trace: {traceback.format_exc()}")
            flash("Face verification failed. Please try again.", 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", 'success')
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user' not in session:
        flash("Please login first.", 'warning')
        return redirect(url_for('login'))
    return render_template('home.html')
    

if __name__ == '__main__':
    app.run(debug=True)
