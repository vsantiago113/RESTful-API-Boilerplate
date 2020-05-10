from flask import Flask, request, make_response, jsonify, Response
from flask_restx import Resource, Api, abort, reqparse
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from datetime import timedelta
import random

app = Flask(__name__)
app.secret_key = 'mysupersecretkey'
api = Api(app, version='1.0', title='My API Boilerplate',
          description='My API Boilerplate',
          )
ns = api.namespace('api/v1', description='Example.')

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_TOKEN_LOCATION'] = 'headers'
app.config['JWT_HEADER_NAME'] = 'X-Example-access-token'
app.config['JWT_HEADER_TYPE'] = ''
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

blacklist = set()

devices = {
    'routers': {
        12345: {
            'name': 'RT1',
            'ip': '192.168.1.101'
        },
        123456: {
            'name': 'RT2',
            'ip': '192.168.1.102'
        },
        123457: {
            'name': 'RT3',
            'ip': '192.168.1.103'
        },
        12345712: {
            'name': 'RT4',
            'ip': '192.168.1.104'
        },
        12345752: {
            'name': 'RT5',
            'ip': '192.168.1.105'
        }
    }
}


def generate_device_id():
    return random.randint(10000, 20000)


@ns.route('/generatetoken')
class GenerateToken(Resource):
    @staticmethod
    def post():
        if request.authorization.username == 'admin' and request.authorization.password == 'Admin123':
            access_token = create_access_token(identity=request.authorization.username, fresh=True)
            refresh_token = create_refresh_token(identity=request.authorization.username)
            return Response(headers={'X-Example-access-token': access_token,
                                     'X-Example-refresh-token': refresh_token})
        else:
            return make_response(jsonify({'message': 'Bad username or password'}), 401)


@ns.route('/refreshtoken')
class RefreshToken(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return Response(headers={'X-Example-access-token': access_token,
                                 'X-Example-refresh-token': request.headers.get('X-Example-access-token')})


@ns.route('/revoketoken')
class RevokeToken(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        blacklist.add(jti)
        return make_response(jsonify({'msg': 'Successfully logged out'}), 200)


@ns.route('/lets_get_all_routers')
class TestRouters(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('PageSize', type=int, location='args')
        parser.add_argument('Offset', type=int, location='args')
        args = parser.parse_args()
        if not args.PageSize:
            page_size = 10
        else:
            page_size = args.PageSize
        if page_size > 100:
            raise reqparse.exceptions.RequestEntityTooLarge('PageSize cannot exceed 100 items!')
        if not args.Offset:
            offset = 0
        elif args.Offset > page_size:
            offset = 0
        else:
            offset = args.Offset
            
        items = []
        for k, v in devices['routers'].items():
            v.update({'id': str(k)})
            items.append({k: v})

        data = {'url': request.url,
                'items': items[offset:page_size],
                'PageSize': page_size,
                'Offset': offset,
                'count': len(items[offset:page_size])}
        return make_response(jsonify(data), 200)


@ns.route('/routers')
class ListRouters(Resource):
    @jwt_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('PageSize', type=int, location='args')
        parser.add_argument('Offset', type=int, location='args')
        args = parser.parse_args()
        if not args.PageSize:
            page_size = 10
        else:
            page_size = args.PageSize
        if page_size > 100:
            raise reqparse.exceptions.RequestEntityTooLarge('PageSize cannot exceed 100 items!')
        if not args.Offset:
            offset = 0
        elif args.Offset > page_size:
            offset = 0
        else:
            offset = args.Offset
            
        items = []
        for k, v in devices['routers'].items():
            v.update({'id': str(k)})
            items.append({k: v})

        data = {'url': request.url,
                'items': items[offset:page_size],
                'PageSize': page_size,
                'Offset': offset,
                'count': len(items[offset:page_size])}
        return make_response(jsonify(data), 200)

    @jwt_required
    def post(self):
        data = request.get_json()
        while True:
            device_id = generate_device_id()
            if device_id not in devices['routers']:
                break
        devices['routers'][device_id] = data
        return make_response(jsonify(devices['routers'][device_id]), 200)


@ns.route('/routers/<int:device_id>')
class Routers(Resource):
    @jwt_required
    def get(self, device_id):
        try:
            device = devices['routers'][device_id]
        except KeyError:
            abort(404)
        else:
            return make_response(jsonify(device), 200)

    @jwt_required
    def put(self, device_id):
        data = request.get_json()
        devices['routers'][device_id].update(data)
        return make_response(jsonify(devices['routers'][device_id]), 200)

    @jwt_required
    def delete(self, device_id):
        devices['routers'].pop(device_id, None)
        return make_response(jsonify(devices['routers'][device_id]), 200)


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


app.run(debug=True)
