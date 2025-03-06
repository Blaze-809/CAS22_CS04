from flask import Flask, render_template, request
from scanner import scan_website

app = Flask(__name__, template_folder="templates")  

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form.get("url")  # Get the URL from the form
        if url:
                results = scan_website(url)  # Scan the website for vulnerabilities
                return render_template("results.html", url=url, results=results)  # Show results page
    return render_template("index.html")  # Show input form initially

if __name__ == "__main__":
    app.run(debug=True)