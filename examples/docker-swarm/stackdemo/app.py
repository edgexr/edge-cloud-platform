from flask import Flask
from redis import Redis
import requests

app = Flask(__name__)
redis = Redis(host='redis', port=6379)

@app.route('/')
def hello():
    count = redis.incr('hits')
    response = requests.get("https://api.ipify.org?format=json")
    return 'Hello World! I have been seen {0} times. IP address {1}\n'.format(count,response.json()["ip"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
