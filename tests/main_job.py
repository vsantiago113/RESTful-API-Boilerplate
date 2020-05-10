import requests
from requests.auth import HTTPBasicAuth
import json

response = requests.post('http://127.0.0.1:5000/api/v1/generatetoken',
                         auth=HTTPBasicAuth('admin', 'Admin123'), verify=False)
token = response.headers.get('X-Example-access-token')
refresh_token = response.headers.get('X-Example-refresh-token')
print(token)
print(refresh_token)

response = requests.get('http://127.0.0.1:5000/api/v1/routers', headers={'Content-Type': 'application/json',
                                                                         'X-Example-access-token': token}, verify=False)
print(json.dumps(response.json(), indent=4))

response = requests.post('http://127.0.0.1:5000/api/v1/refreshtoken',
                         headers={'Content-Type': 'application/json', 'X-Example-access-token': refresh_token},
                         verify=False)
token = response.headers.get('X-Example-access-token')
refresh_token = response.headers.get('X-Example-refresh-token')
print(token)
print(refresh_token)

response = requests.post('http://127.0.0.1:5000/api/v1/routers',
                         headers={'Content-Type': 'application/json', 'X-Example-access-token': token}, verify=False,
                         json={'name': 'RT99', 'ip': '192.168.1.199'})
print(json.dumps(response.json(), indent=4))

response = requests.get('http://127.0.0.1:5000/api/v1/routers', params={'PageSize': 100, 'Offset': 0},
                        headers={'Content-Type': 'application/json', 'X-Example-access-token': token}, verify=False)
print(json.dumps(response.json(), indent=4))

response = requests.get('http://127.0.0.1:5000/api/v1/lets_get_all_routers', params={'PageSize': 100, 'Offset': 0},
                        headers={'Content-Type': 'application/json', 'X-Example-access-token': token}, verify=False)
print(json.dumps(response.json(), indent=4))
