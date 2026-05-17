from flask import Flask, render_template, jsonify
from scanner import scan_network, get_alerts, check_for_alerts

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

@app.route('/api/devices')
def api_devices():
    device_list = scan_network()
    check_for_alerts(device_list)
    return jsonify(device_list)

# NEW — Alerts page
@app.route('/alerts')
def alerts():
    alert_list = get_alerts()
    return render_template('alerts.html', alerts=alert_list)

# NEW — JSON API for alerts
@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_alerts())

if __name__ == "__main__":
    app.run(debug=True)