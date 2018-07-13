from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def my_form():
    return ('<form method="POST"><input name="text"><input type="submit"></form>')

@app.route('/', methods=['POST'])
def my_form_post():
    text = request.form['text']
    processed_text = text.upper()
    return processed_text
app.run(host='0.0.0.0',port=1222)
