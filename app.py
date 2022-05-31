from flask import Flask, request, jsonify, Response, make_response, abort


from flask_mongoengine import MongoEngine
import urllib
import validators
from werkzeug.security import (check_password_hash, generate_password_hash)
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity





# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
  


# from requests import request, jsonify

app = Flask(__name__)

database_name  = "flask-crud-DB"
password = "toffy123"
DB_URI = "mongodb+srv://flask_crud_admin:"+ urllib.parse.quote(password) +"@clusterv1.hgdkzz9.mongodb.net/?retryWrites=true&w=majority"

# mongo_uri = "mongodb://username:" + urllib.quote("p@ssword") + "@127.0.0.1:27001/"

app.config["MONGODB_HOST"] = DB_URI

secret_key_string = 'flask-crud-api&05bm5^wlyw%^emin36d7up(+=2p2g6^7ghv(r&yt1jg8f620*'

app.config["SECRET_KEY"] = secret_key_string
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=100)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)


db = MongoEngine()
# db = MongoEngine(app)

db.init_app(app)
JWTManager(app )


class User(db.Document):
    # fest, last, email, password 
    user_id = db.IntField()
    email = db.StringField(required=True)
    first_name = db.StringField()
    last_name = db.StringField()
    password = db.StringField()

    def to_json(self):

        return {
            "user_id" : self.user_id,
            "first_name" : self.first_name,
            "last_name" : self.last_name,
            "email" : self.email,
            "password" : self.password,
        }


class Template(db.Document):
    template_id = db.IntField()
    author = db.ReferenceField(User)
    template_name = db.StringField(max_length=120, required=True)
    subject = db.StringField()
    body = db.StringField()
    password = db.StringField()
    




# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.json
    # print("ere")
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify email or password is missing',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
    user = User.objects(email = auth.get('email')).first()

    if not user:

        return make_response(
            'Could not verify user does not exist',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )  
    if check_password_hash(user.password, auth.get('password')):
        token = create_access_token(identity=str(user.id))
        try:
            access_token = token.decode("utf-8")
            return jsonify({"access_token": access_token}), 201

        except Exception as e:
            access_token = token
            return jsonify({"access_token": access_token}), 201

    return jsonify({"message":"Could not verify your identity"}), 403
    

@app.route('/register', methods=["POST"])
def register():
    try: 
        email = request.json["email"]
        first_name = request.json["first_name"]
        last_name = request.json["last_name"]
        password = request.json["password"]
        if len(password)<6:
            return jsonify({"message":"passwordis too short"}), 400
        # print(email, first_name, last_name)
        if not validators.email(email):
            return jsonify({"message":"invalid email"}), 400
        exists = User.objects(email = email ).first()
        if exists :
            return jsonify({"message":"Email already exist"}), 400

        pwd_hash = generate_password_hash(password)
        user = User(email = email, first_name = first_name, last_name = last_name, password = pwd_hash)
        user.save()
        return jsonify({"message":"user created"}), 200
    except Exception as e:
        # print(e)
        return jsonify({"message":e}), 400


# User Database Route
# this route sends back list of users
@app.route('/template', methods =["GET", "POST"])
# @token_required
@jwt_required()
def get_my_templates():
    logged_in_user = get_jwt_identity()
    if request.method == "GET":
        # print(str(logged_in_user))
        templates = Template.objects(author = logged_in_user)
        output = []
        for template in templates:
            output.append({
                'id': str(template.id),
                'template_name' : template.template_name,
                'subject': template.subject,
                'body' : template.body,

            })
        return jsonify({'templates': output})
    elif request.method == "POST":
        try:
            template_name = request.json['template_name']
            subject = request.json['subject']
            body = request.json['body']
            
        except LookupError as e:
            return make_response(e.args[0], 400)
        try:
            created_template = Template(template_name= template_name, subject= subject, body= body, author = logged_in_user)
            created_template.save()

            return make_response("template created", 201)
        except Exception as e:
             return make_response(e.args[0], 400)
    else:

        return make_response("method not allowed", 400)




# 6293b4261b6e495b0e70f806
# User Database Route
# this route sends back list of users
@app.route('/template/<template_id>', methods =['GET', 'PUT', 'DELETE'])
# @token_required
@jwt_required()
def get_post_put_delete_template(template_id):
    logged_in_user = get_jwt_identity()
    template_object = Template.objects(id=template_id, author = logged_in_user).first()
    if template_object is None:
        return make_response("Template Not found", 404)
    if request.method == "GET":
        # querying the database

        output = {
            "id": str(template_object.id),
            "author": template_object.author.email,
            "template_name": template_object.template_name,
            'subject': template_object.subject,
            "body": template_object.subject
        }
        return output , 200
    elif request.method == "PUT":
        content = request.json
        # template_object = Template.objects(id = template_id).first()
        template_object.update(template_name = content['template_name'], subject = content["subject"], body = content["body"])
        return make_response("", 204)
    elif request.method == "DELETE":
        # template_object = Template.objects(id = template_id).first()
        template_object.delete()
        return make_response("", 204)
    else:
        return make_response("", 200)

if __name__ =="__main__":
    app.run()