import json


def url(domain):
    with open(domain + '/urls.json') as json_file:
        d = json.load(json_file)
        return d


def getvalue():
    with open('192.168.1.70/urls.json') as json_file:
        d = json.load(json_file)
    for key, value in d.items():
        return value[0]
