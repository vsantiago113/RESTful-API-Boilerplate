import requests
from requests.auth import HTTPBasicAuth
import json

response = requests.post('http://127.0.0.1:5000/generatetoken',
                         auth=HTTPBasicAuth('admin', 'Admin123'), verify=False)
token = response.headers.get('access-token')
refresh_token = response.headers.get('refresh-token')
print(token)
print(refresh_token)

response = requests.get('http://127.0.0.1:5000/test', headers={'Content-Type': 'application/json',
                                                               'access-token': token}, verify=False)
print(json.dumps(response.json(), indent=4))

response = requests.post('http://127.0.0.1:5000/refreshtoken',
                         headers={'Content-Type': 'application/json', 'access-token': refresh_token},
                         verify=False)
token = response.headers.get('access-token')
refresh_token = response.headers.get('refresh-token')
print(token)
print(refresh_token)
