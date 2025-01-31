from flask import Flask, request, jsonify
import pandas as pd
from flask_cors import CORS
import pickle

app = Flask(__name__)

CORS(app, resources={r"/*":{"origins":"*"}})
model = pickle.load(open('ml_model.pkl', "rb"))

@app.route('/', methods=['GET'])
def get_data():
    data = {
        "message":"API is Running"
    }
    return jsonify(data)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        query_df = pd.DataFrame([data])
        prediction = model.predict(query_df)
        return jsonify({'Prediction': list(prediction)})
    except Exception as e:
        return jsonify({'error': str(e)})
    
if __name__ == '__main__':
    app.run(debug=True, port=5000)