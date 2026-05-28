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

# In-memory store for the last analysis result
# This lets supporting endpoints access the data without re-running analysis
last_report = None


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
    and returns a JSON report. Also stores the result for other endpoints.

    Returns:
        200: analysis report as JSON
        400: bad request (missing file, wrong type, empty file)
        500: analysis failed
    """
    global last_report

    # Check that a file was actually included in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    # Check that the file has a name
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check the file extension
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .log and .txt files are accepted'}), 400

    # Save the file temporarily with a unique name
    unique_filename = f"{uuid.uuid4().hex}.log"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    # Check the file isn't empty
    if os.path.getsize(filepath) == 0:
        os.remove(filepath)
        return jsonify({'error': 'Uploaded file is empty'}), 400

    # Run the analysis
    try:
        report = generate_report(filepath)
        last_report = report
        return jsonify(report), 200

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

    finally:
        # Always delete the temp file, even if analysis failed
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/api/summary', methods=['GET'])
def summary():
    """
    Returns just the summary section of the last analysis.

    Returns:
        200: summary dict with total_requests, unique_ips, etc.
        404: no analysis has been run yet
    """
    if last_report is None:
        return jsonify({'error': 'No analysis run yet. Upload a log file first.'}), 404

    return jsonify(last_report['summary']), 200


@app.route('/api/anomalies', methods=['GET'])
def anomalies():
    """
    Returns all scored anomalies from the last analysis.

    Returns:
        200: list of anomaly objects sorted by risk score
        404: no analysis has been run yet
    """
    if last_report is None:
        return jsonify({'error': 'No analysis run yet. Upload a log file first.'}), 404

    return jsonify({
        'anomaly_counts': last_report['anomaly_counts'],
        'all_scores':     last_report['all_scores'],
        'top_offenders':  last_report['top_offenders'],
    }), 200


@app.route('/api/timeline', methods=['GET'])
def timeline():
    """
    Returns the requests-per-hour timeline from the last analysis.

    Returns:
        200: list of {hour, count} objects
        404: no analysis has been run yet
    """
    if last_report is None:
        return jsonify({'error': 'No analysis run yet. Upload a log file first.'}), 404

    return jsonify({
        'timeline': last_report['timeline']
    }), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)