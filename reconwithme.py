import requests
import sys
import re  # Regex
import json
import os
import mysql.connector
import threading
import dns.resolver  # DNS python to get NS,A,Cname records
from os import path as paths
from urllib.parse import urlparse, parse_qs # parsing URL


class myThread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        dirsearch(self.name, self.counter, self.threadID)


url = str(sys.argv[1])
thread = str(sys.argv[2])
r = requests.get(url);  # Send GET request to the URL
h = requests.head(url);  # Get HTTP Headers


def db():
    global mydb
    global mycursor
    try:
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="",
            database="Reconwithme"
        )
        mycursor = mydb.cursor()
    except:
        print("\033[31m[-] Please Turn on Mysql Database port\033[0m")
        sys.exit()


def serverDetails():
    if 'server' in h.headers:
        get_server = h.headers['server']
        print("          ----------------------------------------------------------")
        print("          |Server      ||     \033[31m" + get_server + "\033[0m          ")
        ns = dns.resolver.query('tutorialspoint.com', 'ns')
        for ipval in ns:
            print("          ----------------------------------------------------------")
            print("          |Nameserver  ||     \033[31m" + ipval.to_text() + "\033[0m          ")
        a = dns.resolver.query('tutorialspoint.com', 'A')
        for ipval in a:
            print("          ----------------------------------------------------------")
            print("          |A Record    ||     \033[31m" + ipval.to_text() + "\033[0m          ")
            print("          ----------------------------------------------------------")
    elif 'Location' in h.headers:
        get_server = h.headers['Location']
        get_redirected_header = (requests.head(get_server)).headers
        if 'server' in get_redirected_header:
            print(
                "[-] The site you are searching for vulnerability is using" + get_redirected_header[
                    'server'] + "Server")
        else:
            print("\033[33m[+] Unable to find server details\033[0m")
    else:
        print("\033[33m[+] Unable to find server details\033[0m")


def scrape():
    s = r.content
    html = s.decode('ISO-8859-1')
    data = {'URL': []}
    global domain
    domain = ((url.replace("www.", "")).replace("https://", "")).replace('/', '')
    urls = re.findall(
        'http[s]?://' + re.escape(domain) + '/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        html)  # http://urlregex.com/
    get_json = json.dumps({"url": urls})
    json_file = json.loads(get_json)
    # define the name of the directory to be created
    file = url.replace('/', '')
    path = os.getcwd() + "/" + domain
    if str(paths.exists(domain)):
        os.system('rm -rf ' + domain)
    os.mkdir(path)
    write_json = []
    for i in range(len(json_file['url'])):
        s = re.match(r"(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png|js|swf|css)", json_file['url'][i])
        if s is None:
            write_json.append(json_file['url'][i])
    write_json_file = json.dumps({"url": write_json})
    f = open(path + "/urls.json", "w")
    f.write(str(write_json_file))
    f.close()


def clickjacking():
    with open(domain + '/urls.json') as json_file:
        d = json.load(json_file)
        clickjacking_url = []
        for i in range(len(d['url'])):
            print(d['url'])
            req_header = requests.head(d['url'][i]);
            try:
                if req_header.headers['X-Frame-Options'] == "DENY" or "SAMEORIGIN":
                    print("  \033[34m               [+] Prevented from Clickjacking \033[0m \n");
            except:
                clickjacking_url.append(d['url'][i])
                print("  \033[31m                [+] Vulnerable to Clickjacking \033[0m\n");
        sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
        val = (url, 'Clickjacking Vulnerability',
               'Clickjacking is a malicious technique of tricking a user into clicking on something different from what the user perceives, thus potentially revealing confidential information or allowing others to take control of their computer while clicking on seemingly innocuous objects, including web pages',
               'Clickjacking',
               '1) Make a HTML file like this \n <html><iframe src="' + url + '"><html> \n 2) Open html file then it will be loaded in iframe  automatically 3) You can change the url to any below url' + str(
                   clickjacking_url), 'Medium')
        mycursor.execute(sql, val)
    mydb.commit()


def search(d, lookup):
    for key, value in d.items():
        for v in value:
            if lookup in v:
                return v


def openRedirect():
    with open(domain + '/urls.json') as json_file:
        d = json.load(json_file)
    if search(d, 'return_url'):
        print("URL found")


def xss():
    try:
        if h.headers['X-XSS-Protection'] == "1":
            print(" \033[34m                 [+] Prevented from XSS \033[0m \n");
    except:
        print(
            "   \033[31m              [+] This website might be Vulnerable to XSS, furthur testing report will be displayed soon \033[0m\n");


def sqlinjection():
    with open('nassec.io/urls.json') as json_file:
        d = json.load(json_file)
    sqli_url = []
    for i in range(len(d['url'])):
        search_param = re.search(r"[\?]", d['url'][i])
        if search_param is not None:
            sqli_url.append(d['url'][i])
    sqli_url = json.dumps({"url": sqli_url})
    sqli = json.loads(sqli_url)
    for i in range(len(sqli['url'])):
        sqli_parse = urlparse(sqli['url'][i])
        query = parse_qs(sqli_parse.query)
        sqli_url = sqli_parse._replace(query=None).geturl()
        for j in query:
            query[j] = "'"
            sqli_test = requests.get(sqli_url, params=query)
            txt = sqli_test.text
            if 'SQL' in txt:
                print("  \033[31m               [+] Vulnerable to SQL injection \033[0m\n");
            else:
                print(" \033[34m                [+] Prevented from SQL injection \033[0m\n");


def dirsearch(counter, threadID):
    wordlist = open("wordlist/wordlist.txt", "r")
    m = 1
    # print(threadID)
    # print(counter)
    if threadID == 1:
        wordlists = wordlist.readlines(counter)
    else:
        wordlists = wordlist.readlines()[counter * (threadID - 1):counter * threadID]
    for i in wordlists:
        try:
            brute_url = url + i
            brute_request = requests.get(brute_url)
            brute_status = brute_request.status_code
            if brute_status == 200:
                print(str(brute_status) + "                     " + brute_url)
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = []
                for j in brute_url:
                    base = (url, 'Directory Opened',
                            'Directory is opened due to which there is high probability of information disclosure',
                            'Go to ' + brute_url, 'Directory Listing', 'Medium')
                    val.append(base)
                insert = list(dict.fromkeys(val))
                mycursor.executemany(sql, insert)
                mydb.commit()
        except:
            brute_url = url + "/" + i
            brute_request = requests.get(brute_url)
            brute_status = brute_request.status_code
            if brute_status == 200:
                print(str(brute_status) + "                     " + brute_url)
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = []
                for j in brute_url:
                    base = (url, 'Directory Opened',
                            'Directory is opened due to which there is high probability of information disclosure',
                            'Go to ' + brute_url, 'Directory Listing', 'Medium')
                    val.append(base)
                insert = list(dict.fromkeys(val))
                mycursor.executemany(sql, insert)
                mydb.commit()


def dirsearchThread():
    wordlist_number = open("wordlist/wordlist.txt", "r")
    t = int(thread)
    number = int(len(wordlist_number.readlines()) / t)
    for i in range(1, t + 1):
        myThread(i, "Thread" + str(i), number).start()


#    thread1 = myThread(1, "Thread-1", 500)
#    thread2 = myThread(2, "Thread-2", 1273719)
#    thread1.start()
#    thread2.start()
def hunterApi():
    getUrl = (url.replace('www.', '')).replace('https://', '')
    getEmail = requests.get(
        "https://api.hunter.io/v2/domain-search?domain=" + getUrl + "&api_key=2250e2aa3fa45e6cc0b6a15a6c991f5c4a4c3cd8")
    getContent = getEmail.content
    getJson = json.loads(getContent)
    emails = []
    print("Publicly Accessible Emails:")
    for i in range(len(getJson['data']['emails'])):
        email = getJson['data']['emails'][i]['value']
        print("\033[31m" + email + "\033[0m")
        os.system('proxychains4 python3 Tor/tor.py' + " " + email + "|sed -n -e '/^1$/,/^61$/p'")
        listEmail = list(email.split(" "))
        emails = emails + listEmail
    # Checking Emails over Tor


def main():
    print("Pwning like you Own it")
    print("\033[31m")
    print("""                ____                              _ _   _     __  __""" + """
                |  _ \ ___  ___ ___  _ ____      _(_) |_| |__ |  \/  | ___
                | |_) / _ \/ __/ _ \| '_ \ \ /\ / / | __| '_ \| |\/| |/ _ \ """ + """
                |  _ <  __/ (_| (_) | | | \ V  V /| | |_| | | | |  | |  __/
                |_| \_\___|\___\___/|_| |_|\_/\_/ |_|\__|_| |_|_|  |_|\___|

""" + "   \033[0m                                         Welcome to ReconwithMe\n                                    \033[33m                    Coded by @evilboyajay\033[0m")
    serverDetails()
    print("[-] Scraping the URL's and saving it to JSON file")
    db()
#    scrape()
    print("[-] Checking Clickjacking Vulnerbility")
    #    clickjacking()
    print("[-] Checking SQL Injection Vulnerbility")
    sqlinjection()
    print("[-] Checking Javascript Injection Vulnerbility")
    #    xss()
    print("[-] Checking Public email is leakage")
    #    hunterApi()
    print("[-] Checking Open  Redirect Vulnerbility")
    #    openRedirect()
    print("[-] Checking Directory Listing Vulnerbility \n")
    print("\033[31m Please be patient this will take longer time\033[0m")
    print("Status                      Directory")
    print("_________                   __________ ")
    # Directory Bruteforce Using threading


#    dirsearchThread()


main()
