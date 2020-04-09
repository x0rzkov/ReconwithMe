import requests
import sys
import re  # Regex
import json
import scraped_urls  # Reading Url.json
import os
import mysql.connector
import threading
import dns.resolver  # DNS python to get NS,A,Cname records
from os import path as paths
from bs4 import BeautifulSoup  # For getting xss content
from urllib.parse import urlparse, parse_qs  # parsing URL


class myThread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        dirsearch(self.counter, self.threadID)


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
    domain = (((url.replace("www.", "")).replace("https://", "")).replace('/', '')).replace("http:", "")
    full_urls = []
    urls = re.findall(
        'http[s]?://' + re.escape(domain) + '/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        html)  # http://urlregex.com/
    full_urls = full_urls + urls
    loop = 1
    while loop == 1:
        if len(full_urls) == 0:
            loop = 2
        else:
            for i in range(len(full_urls)):
                url_req = requests.get(full_urls[i])
                url_content = url_req.content
                response_url = url_content.decode('ISO-8859-1')
                urlss = re.findall('http[s]?://' + re.escape(
                    domain) + '/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                   response_url)  # http://urlregex.com/
                for j in range(len(urlss)):
                    if urlss[j] not in full_urls:
                        full_urls.append(urlss[j])
                        loop = 1
                    else:
                        loop = 2
    print(full_urls)
    get_json = json.dumps({"url": full_urls})
    json_file = json.loads(get_json)
    # define the name of the directory to be created
    file = url.replace('/', '')
    path = os.getcwd() + "/" + domain
    if str(paths.exists(domain)):
        os.system('rm -rf ' + domain)
        sql = "DELETE FROM `Vulnerabilities` WHERE url LIKE '%" + domain + "%'"
        mycursor.execute(sql)
        mydb.commit()
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
                       '1) Make a HTML file like this <br> &lt;html&gt;<br>&lt;iframe src="' + url + '"&gt;<br>&lt;html&gt; <br> 2) Open html file then it will be loaded in iframe  automatically 3) You can change the url to any below url' + str(
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
    xss_urls = scraped_urls.url(domain)
    xss_parameter_url = sqli_xss(xss_urls)
    xss_parameter_url = json.loads(xss_parameter_url)
    for i in range(len(xss_parameter_url['url'])):
        xss_request = requests.get(xss_urls['url'][i])
        xss_request_headers = xss_request.headers
        if 'X-XSS-Protection' in xss_request_headers:
            if xss_request_headers['X-XSS-Protection'] == 1 in xss_urls['url']:
                print(" \033[34m                 [+] Prevented from XSS \033[0m \n");
        else:
            print(
                "   \033[34m             [+] This parameter might be Vulnerable to XSS, furthur testing report will be displayed soon \033[0m");
    for key, value in xss_urls.items():
        for v in value:
            xss_payload = v + "\"><script>alert(0)</script>"
            xss_database = v + "\"&gt;&lt;script&gt;alert(0)&lt;/script&gt;"
            img_xss(xss_database, xss_payload)


def img_xss(xss_database, xss_payload):
    xss_check = requests.get(xss_payload)
    xss_source_check = xss_check.content
    soup = BeautifulSoup(xss_source_check, 'html.parser')
    confirm_script_xss = soup.find_all("script")
    for x in confirm_script_xss:
        if x.text.strip() == "alert(0)":
            print(" \033[31m               [+] Vulnerable to XSS \033[0m")
            print("                        Payload: " + xss_payload)
            sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
            val = (url, "<span style='color: red ;'><b>Reflected</b></span> Xss at " + xss_database,
                   "A reflected XSS (or also called a non-persistent XSS attack) is a specific type of XSS whose malicious script bounces off of another website to the victim's browser. It is passed in the query, typically, in the URL. It makes exploitation as easy as tricking a user to click on a link",
                   "XSS",
                   "1) Go to  " + xss_database + "<br>2) When you click above URL, xss will be fired ",
                   "<span style='color: red ;'>High</b></span>")
            mycursor.execute(sql, val)
            mydb.commit()


def sqli_xss(d):
    sqli_url = []
    for i in range(len(d['url'])):
        search_param = re.search(r"[\?]", d['url'][i])
        if search_param is not None:
            sqli_url.append(d['url'][i])
    sqli_url = json.dumps({"url": sqli_url})
    return sqli_url


def sqlinjection():
    with open(domain + '/urls.json') as json_file:
        d = json.load(json_file)
    sqli_url = []
    for i in range(len(d['url'])):
        search_param = re.search(r"[\?]", d['url'][i])
        if search_param is not None:
            sqli_url.append(d['url'][i])
    sqli_url = json.dumps({"url": sqli_url})
    sqli = json.loads(sqli_url)
    for key, value in sqli.items():
        for v in value:
            timebased = v + "-sleep(5)"
            time_request = requests.get(timebased)
            resp_time = str(round(time_request.elapsed.total_seconds(), 2))
            if float(resp_time) > 10:
                print(timebased)
                print(
                    "          [+] Vulnerable to Time Based SQL Injection\n\033[31m          [-]Payload: " + timebased + "\033[0m\n")
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = (url, "[<span style='color: red ;'><b>[Critical]</b></span> Error Based SQL Injection",
                       "Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database.",
                       "SQL Injection",
                       "1) Go to  " + timebased + "<br>2) You will notice that it takes more time to load than usual",
                       "High")
                mycursor.execute(sql, val)
                mydb.commit()
    for i in range(len(sqli['url'])):
        sqli_parse = urlparse(sqli['url'][i])
        query = parse_qs(sqli_parse.query)
        query1 = parse_qs(sqli_parse.query)
        sqli_url = sqli_parse._replace(query=None).geturl()
        for j in query:
            initial_request = requests.get(sqli_url, params=query)
            query[j] = "'"
            sqli_test = requests.get(sqli_url, params=query)
            txt = sqli_test.text
            if 'SQL' in txt:
                print("\033[31m          [-] Checking for Error-Based SQLi \033[0m\n");
                errorSqli(sqli_url, query1, initial_request)
            else:
                print("\033[34m          [+] Prevented from SQL injection \033[0m\n");


def errorSqli(sqli_url, query, initial_request):
    for i in query:
        for key, value in query.items():
            for v in value:
                sqli_url1 = sqli_url + "?" + i + "=" + v + "%20AND%201=1"
                confirmSqli = requests.get(sqli_url1)
                if initial_request.text == confirmSqli.text:
                    query[i] = "%20AND 1=2"
                    confirmSqli = requests.get(sqli_url, params=query)
                    if initial_request.text != confirmSqli.text:
                        print(
                            "          [+] Vulnerable to Error Based SQL Injection\n\033[31m          [-]Payload: " + sqli_url1 + "\033[0m\n")
                        sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                        val = (url, "[Critical] Error Based SQL Injection",
                               "Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database.",
                               "SQL Injection",
                               "1) Go to  " + sqli_url1 + "<br>2) Add ' at the end of the URL you will see SQL error",
                               "High")
                        mycursor.execute(sql, val)
                        mydb.commit()
                elif initial_request.text != confirmSqli.text:
                    sqli_url1 = sqli_url + "?" + i + "=" + v + " OR 1=1"
                    confirmOrSqli = requests.get(sqli_url1)
                    if confirmSqli.text != confirmOrSqli.text:
                        print(
                            "          [+] Vulnerable to Error Based SQL Injection\n\033[31m          [-]Payload: OR 1=1\033[0m\n")
                        sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                        val = (url, "[Critical] Error Based SQL Injection",
                               "Error-based SQLi is an in-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database. In some cases, error-based SQL injection alone is enough for an attacker to enumerate an entire database.",
                               "SQL Injection",
                               "1) Go to  " + sqli_url1 + "<br>2) Add ' at the end of the URL you will see SQL error",
                               "High")
                        mycursor.execute(sql, val)
                        mydb.commit()


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
            print("test")
            if brute_status == 200:
                print(str(brute_status) + "                     " + brute_url)
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = []
                for j in brute_url:
                    base = (url, 'Directory Opened',
                            'Directory is opened due to which there is high probability of information disclosure',
                            'Directory Listing',
                            'Go to ' + brute_url, 'Medium')
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
                            'Directory Listing',
                            '1) Go to ' + brute_url+'<br>2) You will see you can access file or directory', 'Medium')
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
        mydb.commit()
        os.system('proxychains4 python3 Tor/tor.py' + " " + email + "|sed -n -e '/^1$/,/^61$/p'")
        listEmail = list(email.split(" "))
        emails = emails + listEmail
    sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
    val = (url, 'Email is publicly available',
           'Your emails are publicly accessible from search engines. Spammer can get your email for spamming as well as if your email has suffered from any database leakage then attack can access your password too, if not changed',
           'Email Disclosure',
           '1) Go to hunter.io <br>2)Search your company name <br>3) Your email will be displayed <span style="color: red ; text-align: justify;"><br>' + str(emails) + '</span>', 'Low')
    mycursor.execute(sql, val)
    mydb.commit()
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
    scrape()
    print("[-] Checking Clickjacking Vulnerbility")
    clickjacking()
    print("[-] Checking SQL Injection Vulnerbility")
    sqlinjection()
    print("[-] Checking Javascript Injection Vulnerbility")
    xss()
    print("[-] Checking Public email is leakage")
    hunterApi()
    print("[-] Checking Open  Redirect Vulnerbility")
    openRedirect()
    print("[-] Checking Directory Listing Vulnerbility \n")
    print("\033[31m Please be patient this will take longer time\033[0m")
    print("Status                      Directory")
    print("_________                   __________ ")
    # Directory Bruteforce Using threading
    dirsearchThread()


main()
