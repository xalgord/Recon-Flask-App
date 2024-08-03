from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import subprocess
import threading

app = Flask(__name__)

# Define your upload folder and script path
UPLOAD_FOLDER = '/root/uploads'
SCRIPT_PATH = '/root/auto3.sh'
OUTPUT_DIR = "/root/targets/all"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def run_script(file_path):
    """Function to run the script with the uploaded file as an argument."""
    try:
        subprocess.call([SCRIPT_PATH, file_path])
    except Exception as e:
        print(f"Error running script: {e}")

@app.route('/')
def index():
    files = ["juice_subs.txt", "possible-xss.txt", "new.txt", "vulns.txt", "dirsearch.txt"]
    file_contents = {}
    for file in files:
        file_path = os.path.join(OUTPUT_DIR, file)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                file_contents[file] = f.read()
        else:
            file_contents[file] = "File not found or empty."
    return render_template('upload_and_execute.html', file_contents=file_contents)

@app.route('/<path:filename>')
def download_file(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)

@app.route('/upload_and_execute', methods=['POST'])
def upload_and_execute():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part', 'status': 'error'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file', 'status': 'error'})
    if file:
        # Save the uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Run the script in a separate thread
        threading.Thread(target=run_script, args=(file_path,)).start()

        return jsonify({'message': 'File uploaded and script started', 'status': 'success'})

    return jsonify({'message': 'Something went wrong.', 'status': 'error'})

if __name__ == '__main__':
    app.run(debug=True)
