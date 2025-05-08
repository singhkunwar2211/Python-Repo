from flask import Flask, request, render_template, send_file, redirect, url_for
from scanner import generate_ip_range, scan_ips_parallel
from io import BytesIO, StringIO
import csv
import json

app = Flask(__name__)
scan_cache = []

@app.route("/", methods=["GET", "POST"])
def index():
    global scan_cache
    results = []
    error = None
    if request.method == "POST":
        ip_range = request.form.get("ip_range", "")
        try:
            ip_list = generate_ip_range(ip_range)
            results = scan_ips_parallel(ip_list, max_threads=20) # Increased max_threads here too
            scan_cache = results
        except Exception as e:
            error = f"Invalid IP range or scanning error: {str(e)}"
    return render_template("index.html", devices=scan_cache, error=error)

@app.route("/download/<filetype>")
def download(filetype):
    if not scan_cache:
        return redirect(url_for('index'))

    if filetype == "csv":
        text_stream = StringIO()
        writer = csv.DictWriter(text_stream, fieldnames=["ip", "mac", "hostname"])
        writer.writeheader()
        writer.writerows(scan_cache)
        byte_stream = BytesIO(text_stream.getvalue().encode("utf-8"))
        byte_stream.seek(0)
        return send_file(
            byte_stream,
            mimetype="text/csv",
            as_attachment=True,
            download_name="scan_results.csv"
        )

    elif filetype == "json":
        json_data = json.dumps(scan_cache, indent=4)
        byte_stream = BytesIO(json_data.encode("utf-8"))
        byte_stream.seek(0)
        return send_file(
            byte_stream,
            mimetype="application/json",
            as_attachment=True,
            download_name="scan_results.json"
        )

    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
