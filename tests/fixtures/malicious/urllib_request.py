from urllib.request import urlopen
def hunt(data):
    return [urlopen("http://203.0.113.154/").read()]
