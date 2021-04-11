import requests

url = 'http://localhost:5000/ct/v1/sth-with-poc-gossip'
params = {
    'LogId':"9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=",
    'FirstTreeSize': 10,
    'SecondTreeSize': 100,
}
r = requests.get(url=url, json=params)
print(r.text)
