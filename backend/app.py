# backend/app.py
# Flask API for Log Sentinel
# Run locally with: python3 backend/app.py

import sys
sys.path.append('backend')

import os
import uuid
from flask import Flask, jsonify, request
from flask_cors import CORS
from report import generate_report

app = Flask(__name__)
CORS(app)

# Where uploaded files are temporarily stored
UPLOAD_FOLDER = 'data/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Only accept these file extensions
ALLOWED_EXTENSIONS = {'.log', '.txt'}


def allowed_file(filename):
    """
    Checks if the uploaded file has an allowed extension.

    Args:
        filename: the original filename from the upload

    Returns:
        True if allowed, False if not
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    Returns a simple ok status so you can verify the server is running.
    """
    return jsonify({
        'status': 'ok',
        'message': 'Log Sentinel API is running'
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint.

    Accepts a log file upload, runs the full analysis pipeline,
    and returns a JSON report.

    Returns:
        200: analysis report as JSON
        400: bad request (missing file, wrong type, empty file)
        500: analysis failed
    """

    # Step 1: check that a file was actually included in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    # Step 2: check that the file has a name
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Step 3: check the file extension
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .log and .txt files are accepted'}), 400

    # Step 4: save the file temporarily with a unique name
    # uuid4() generates a random unique ID — prevents filename collisions
    unique_filename = f"{uuid.uuid4().hex}.log"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    # Step 5: check the file isn't empty
    if os.path.getsize(filepath) == 0:
        os.remove(filepath)
        return jsonify({'error': 'Uploaded file is empty'}), 400

    # Step 6: run the analysis
    try:
        report = generate_report(filepath)
        return jsonify(report), 200

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

    finally:
        # Step 7: always delete the temp file, even if analysis failed
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == '__main__':
    app.run(debug=True, port=5000)