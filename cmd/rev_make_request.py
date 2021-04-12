import requests

url = 'http://localhost:5000/ct/v1/srd-with-revdata-gossip'
params = {
    'LogId':"eMj/JnboS5r42I9T4Iq3uRIXRn15EQUbYtAcDMMYT84=",
    'PercentRevoked': 10,
    'TotalCerts': 100,
}
r = requests.get(url=url, json=params)
print(r.text)

