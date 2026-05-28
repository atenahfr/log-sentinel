# backend/app.py
# Flask API for Log Sentinel
# Run locally with: python3 backend/app.py

import sys
sys.path.append('backend')

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


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


if __name__ == '__main__':
    app.run(debug=True, port=5000)