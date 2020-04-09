import json


def url(domain):
    with open(domain+'/urls.json') as json_file:
        d = json.load(json_file)
        return d
