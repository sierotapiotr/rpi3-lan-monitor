from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
  return "<html><body><h1>Raspberry Pi 3 LAN Monitor</h1></body></html>"

if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)