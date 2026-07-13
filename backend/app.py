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
CORS(app, origins=[
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'https://atenahfr.github.io'
])

# Where uploaded files are temporarily stored
UPLOAD_FOLDER = 'data/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Only accept these file extensions
ALLOWED_EXTENSIONS = {'.log', '.txt'}

# Maximum file size: 16MB
MAX_FILE_SIZE = 16 * 1024 * 1024

# In-memory store for the last analysis result
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


def make_error(message, code):
    """
    Helper that builds a consistent error response.

    Args:
        message: human-readable error description
        code:    HTTP status code

    Returns:
        A Flask JSON response with the error message and status code
    """
    return jsonify({
        'error':  message,
        'status': code
    }), code


@app.route('/api/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    Returns a simple ok status so you can verify the server is running.
    """
    return jsonify({
        'status':  'ok',
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
        400: missing file, empty file, or wrong file type
        413: file too large
        422: file is correct type but wrong format
        500: unexpected analysis failure
    """
    global last_report

    # Check that a file was included in the request
    if 'file' not in request.files:
        return make_error('No file uploaded. Include a file with field name "file".', 400)

    file = request.files['file']

    # Check that the file has a name
    if file.filename == '':
        return make_error('No file selected.', 400)

    # Check the file extension
    if not allowed_file(file.filename):
        return make_error(
            f'Invalid file type "{os.path.splitext(file.filename)[1]}". '
            f'Only .log and .txt files are accepted.', 400
        )

    # Save the file temporarily with a unique name
    unique_filename = f"{uuid.uuid4().hex}.log"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    try:
        # Check file size
        file_size = os.path.getsize(filepath)

        if file_size == 0:
            return make_error('Uploaded file is empty.', 400)

        if file_size > MAX_FILE_SIZE:
            return make_error(
                f'File too large ({file_size / 1024 / 1024:.1f}MB). Maximum size is 16MB.', 413
            )

        # Try to run the analysis
        try:
            report = generate_report(filepath)
        except ValueError as e:
            return make_error(f'File format error: {str(e)}', 422)
        except KeyError as e:
            return make_error(
                'File could not be parsed. '
                'Make sure the file is in Apache/Nginx Combined Log Format.', 422
            )

        # Check that we actually got results — empty parse = wrong format
        if report['summary']['total_requests'] == 0:
            return make_error(
                'No valid log entries found. '
                'Make sure the file is in Apache/Nginx Combined Log Format.', 422
            )

        last_report = report
        return jsonify(report), 200

    except Exception as e:
        return make_error(f'Unexpected error during analysis: {str(e)}', 500)

    finally:
        # Always delete the temp file
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/api/summary', methods=['GET'])
def summary():
    """
    Returns just the summary section of the last analysis.

    Returns:
        200: summary dict
        404: no analysis has been run yet
    """
    if last_report is None:
        return make_error('No analysis run yet. Upload a log file first.', 404)

    return jsonify(last_report['summary']), 200


@app.route('/api/anomalies', methods=['GET'])
def anomalies():
    """
    Returns all scored anomalies from the last analysis.

    Returns:
        200: anomaly counts, scores, and top offenders
        404: no analysis has been run yet
    """
    if last_report is None:
        return make_error('No analysis run yet. Upload a log file first.', 404)

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
        return make_error('No analysis run yet. Upload a log file first.', 404)

    return jsonify({
        'timeline': last_report['timeline']
    }), 200
    
@app.route('/api/demo', methods=['GET'])
def demo():
    """
    Demo endpoint — runs analysis on the built-in sample log file.
    Used for portfolio demonstrations without requiring a file upload.

    Returns:
        200: full analysis report from sample.log
        404: sample log file not found
        500: analysis failed
    """
    sample_path = 'data/sample.log'

    if not os.path.exists(sample_path):
        return make_error('Sample log file not found.', 404)

    try:
        global last_report
        report = generate_report(sample_path)
        last_report = report
        return jsonify(report), 200
    except Exception as e:
        return make_error(f'Demo analysis failed: {str(e)}', 500)


if __name__ == '__main__':
    app.run(debug=True, port=5000)