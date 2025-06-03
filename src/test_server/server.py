from flask import Flask, request

app = Flask(__name__)

@app.route("/get", methods=["GET"])
def get():
    return "Hello, you are communicating with NetViz!"

@app.route("/post", methods=["POST"])
def post():
    payload = request.get_json()

    def pretty_print(payload):
        for key, val in payload.items():
            print(f"{key}: {val}")
    
    return f"Hello, you are communicating with NetViz!\n\nPayload: {pretty_print(payload)}"


if __name__ == "__main__":
    app.run(debug=True, port=5000)
