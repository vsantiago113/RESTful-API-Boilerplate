from flask import Flask, request, make_response, jsonify, Response
from flask_restful import Resource, Api
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity, get_raw_jwt, get_jwt_claims)
from datetime import timedelta

blacklist = set()


class GenerateToken(Resource):
    def post(self):
        if request.authorization.username == 'admin' and request.authorization.password == 'Admin123':
            access_token = create_access_token(identity=request.authorization.username, fresh=True)
            refresh_token = create_refresh_token(identity=request.authorization.username)
            return Response(headers={'access-token': access_token,
                                     'refresh-token': refresh_token})
        else:
            return make_response(jsonify({'message': 'Bad username or password'}), 401)


class RefreshToken(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user,
                                           expires_delta=timedelta(minutes=30))
        return Response(headers={'access-token': access_token,
                                 'refresh-token': request.headers.get('access-token')})


class RevokeToken(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        blacklist.add(jti)
        return make_response(jsonify({"msg": "Successfully logged out"}), 200)


class Testing(Resource):
    @jwt_required
    def get(self):
        current_user = get_jwt_identity()
        claims = get_jwt_claims()
        print(current_user)
        print(claims)
        return make_response(jsonify({'message': 'Hello World!'}), 200)


app = Flask(__name__)
app.secret_key = 'mysupersecretkey'
api = Api(app)

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_TOKEN_LOCATION'] = 'headers'
app.config['JWT_HEADER_NAME'] = 'access-token'
app.config['JWT_HEADER_TYPE'] = ''
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

api.add_resource(GenerateToken, '/generatetoken')
api.add_resource(RefreshToken, '/refreshtoken')
api.add_resource(Testing, '/test')


@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    return {
        'user': identity,
        'limit': 3
    }


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


app.run(debug=True)
