
from pymongo import MongoClient
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from bson.json_util import dumps
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from jwt import PyJWT
import re

app = Flask(__name__)
app.secret_key = "please running"
SECRET_KEY = 'secret_key'


client = MongoClient('localhost', 27017)
db = client.week00
user = db.user


@app.route('/')  # <user> 생성
def layout():  # <user> 변수값을 함수로 넘김
    return render_template('main.html')  # 변수들을 html로 넘김


@app.route('/main', methods=('POST', 'GET'))
def Login_check():
    if request.method == "POST":
        id = request.form.get("user_id", type=str)
        pw = request.form.get("user_pw", type=str)

        if user.find_one({"user_id": id}):
            if id == db.user.find_one({"user_id": id})['user_id']:
                if check_password_hash(db.user.find_one({"user_id": id})['pw_hash'], pw):
                    payload = {
                        'id': id,
                        'exp': datetime.utcnow() + timedelta(hours=24)
                    }
                    token = jwt.encode(
                        payload=payload, key=SECRET_KEY, algorithm='HS256')
                    return render_template('main.html', token=token)

        flash("ID 또는 비밀번호를 다시 확인해주세요.")
        return redirect(url_for('Login_check'))
    else:
        return render_template('main.html')


@app.route('/marker')
def marker():
    token = request.cookies.get('user_token')
    try:
        jwt.decode(token, key=SECRET_KEY, algorithms=['HS256'])

        info_list = list(db.info.find({}, {'_id': False}))
        tech_stack_list = info_list[0]['name']
        tag_list = info_list[1]['name']
        marker_list = list(db.marker.find({}).sort('_id', -1))
        return render_template('marker.html', tech_stack_list=tech_stack_list, tag_list=tag_list, marker_list=dumps(marker_list), token=token)
    except jwt.ExpiredSignatureError:
        return redirect(url_for('layout'))
    except jwt.exceptions.DecodeError:
        return redirect(url_for('layout'))


@app.route('/search_receive', methods=('GET',))
def search_receive():
    token = request.cookies.get('user_token')
    try:
        jwt.decode(token, key=SECRET_KEY, algorithms=['HS256'])

        info_list = list(db.info.find({}, {'_id': False}))
        tech_stack_list = info_list[0]['name']
        tag_list = info_list[1]['name']
        search_tech_stack_give = request.args['search_tech_stack_give']
        search_tag_give = request.args['search_tag_give']
        search_receive = request.args['search_keyword_give']
        keyword_rgx = re.compile(f'.*{search_receive}.*')
        tag_rgx = re.compile(f'.*{search_tag_give}.*')
        tech_stack_rgx = re.compile(f'.*{search_tech_stack_give}.*')
        search_result = list(db.marker.find({"$and": [{'tag': tag_rgx}, {'tech_stack': tech_stack_rgx}, {
                             "$or": [{'title': keyword_rgx}, {'comment': keyword_rgx}]}]}).sort('_id', -1))

        keyword_list = [search_tech_stack_give,
                        search_tag_give, search_receive]
        return render_template('marker.html', tech_stack_list=tech_stack_list, tag_list=tag_list, search_results=dumps(search_result), keyword_list=keyword_list, token=token)
    except jwt.ExpiredSignatureError:
        return redirect(url_for('layout'))
    except jwt.exceptions.DecodeError:
        return redirect(url_for('layout'))


@app.route('/info', methods=['POST'])
def upload_data():
    tech_stack = request.form['tech_stack']
    tag = request.form['tag']
    title_receive = request.form['title_give']
    comment_receive = request.form['comment_give']
    url_receive = request.form['url_give']
    user_id = request.form['user_id']
    data = {
        'tech_stack': tech_stack,
        'tag': tag,
        'title': title_receive,
        'comment': comment_receive,
        'url': url_receive,
        'user_id': user_id
    }
    db.marker.insert_one(data)
    return jsonify({'result': 'success'})


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/user', methods=['POST'])
def User_Data():
    name_receive = request.form['name_give']
    email_receive = request.form['email_give']
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    password_hash = generate_password_hash(pw_receive)

    data = {
        'user_name': name_receive,
        'user_email': email_receive,
        'user_id': id_receive,
        'pw_hash': password_hash
    }
    if user.find_one({'user_email': email_receive}):
        return jsonify({'result': 'email_duplicated'})
    elif user.find_one({'user_id': id_receive}):
        return jsonify({'result': 'id_duplicated'})
    elif db.verified_list.find_one({'$and': [{'name': name_receive}, {'email': email_receive}]}):
        user.insert_one(data)
        return jsonify({'result': 'success'})
    return jsonify({'result': 'not_verified'})


@app.route('/delete_marker', methods=('POST',))
def delete_marker():
    marker_id = request.form.get('marker_id')
    db.marker.delete_one({'_id': ObjectId(marker_id)})
    return jsonify({'result': 'success'})


@app.route('/update_marker', methods=('POST',))
def update_marker():
    marker_id = request.form.get('marker_id')
    update_title = request.form.get('update_title')
    update_comment = request.form.get('update_comment')
    update_url = request.form.get('update_url')
    update_tech_stack = request.form.get('update_tech_stack')
    update_tag = request.form.get('update_tag')

    db.marker.find_one_and_update({'_id': ObjectId(marker_id)}, {'$set': {
                                  'title': update_title, 'comment': update_comment, 'url': update_url, 'tech_stack': update_tech_stack, 'tag': update_tag}})

    return jsonify({'result': 'success'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
