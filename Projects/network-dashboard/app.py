from flask import Flask, render_template, jsonify
from scanner import scan_network

app = Flask(__name__)

@app.route('/')
def home():
    devices = scan_network()
    device_count = len(devices)
    return render_template('home.html', device_count=device_count)

@app.route('/devices')
def devices():
    device_list = scan_network()
    return render_template('devices.html', devices=device_list)

# NEW — JSON API endpoint
@app.route('/api/devices')
def api_devices():
    device_list = scan_network()
    return jsonify(device_list)

if __name__ == "__main__":
    app.run(debug=True)