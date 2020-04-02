import requests
import sys
import re #Regex
import json
import os
import mysql.connector
import pymysql #mysql database connecting
import threading

class myThread (threading.Thread):
   def __init__(self, threadID, name, counter):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.counter = counter
   def run(self):
      dirsearch(self.name, self.counter, self.threadID)
def variables():
    url=str(sys.argv[1])
    thread=str(sys.argv[2])
    r=requests.get(url); # Send GET request to the URL
    h=requests.head(url); # Get HTTP Headers
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
        getServer=h.headers['server']
        print("[-] The site you are searching for vulnerability is using \033[31m"+getServer+"\033[0m Server")
    elif 'Location' in h.headers:
        getServer=h.headers['Location']
        getRedirectedHeader=(requests.head(getServer)).headers
        if 'server' in getRedirectedHeader:
            print("[-] The site you are searching for vulnerability is using"+getRedirectedHeader['server']+"Server")
        else:
            print("\033[33m[+] Unable to find server details\033[0m")
    else:
        print("\033[33m[+] Unable to find server details\033[0m")
def scrape():
    s=(r.content)
    html = s.decode('ISO-8859-1')
    data = {}
    data['URL']=[]
    domain= (url.replace("www.","")).replace("https://","")
    urls = re.findall('http[s]?://domain(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html) #http://urlregex.com/
    jsonfile=json.dumps({"url":urls})
    # define the name of the directory to be created
    file=url.replace('/','')
    path = os.getcwd()+"/"+file

    try:
        os.mkdir(path)
    except OSError:
        print ("Creation of the directory %s failed" % path)
    else:
        print ("Successfully created the directory %s " % path)
    f = open(path+"/urls.json", "w")
    f.write(jsonfile)
    f.close()
def clickjacking():
    with open('https:nassec.io/urls.json') as json_file:
        d=json.load(json_file)
        clickjacking=[]
        for i in range(len(d['url'])):
            reqHeader=requests.head(d['url'][i]);
            try:
                if reqHeader.headers['X-Frame-Options']=="DENY" or "SAMEORIGIN":
                    print("  \033[34m               [+] Prevented from Clickjacking \033[0m \n");
            except:
                clickjacking.append(d['url'][i])
                print("  \033[31m                [+] Vulnerable to Clickjacking \033[0m\n");
        sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
        val = (url,'Clickjacking Vulnerability','Clickjacking is a malicious technique of tricking a user into clicking on something different from what the user perceives, thus potentially revealing confidential information or allowing others to take control of their computer while clicking on seemingly innocuous objects, including web pages.','Clickjacking','1) Make a HTML file like this \n <html><iframe src="'+url+'"><html> \n 2) Open html file then it will be loaded in iframe  automatically 3) You can change the url to any below url'+str(clickjacking),'Medium')
        mycursor.execute(sql, val)
def search(d, lookup):
    for key, value in d.items():
        for v in value:
            if lookup in v:
                return v
def openRedirect():
    with open('https:nassec.io/urls.json') as json_file:
        d=json.load(json_file)
    if search(d, 'return_url'):
        print('test')
def xss():
    try:
        if h.headers['X-XSS-Protection']=="1":
            print(" \033[34m                 [+] Prevented from XSS \033[0m \n");
    except:
        print("   \033[31m              [+] This website might be Vulnerable to XSS, furthur testing report will be displayed soon \033[0m\n");

def sqlinjection():
    txt=r.text;
    if 'sql' in txt:
        print("  \033[31m               [+] Vulnerable to SQL injection \033[0m\n");
    else:
        print(" \033[34m                [+] Prevented from SQL injection \033[0m\n");
def dirsearch(name, counter, threadID):
    wordlist= open("wordlist/wordlist.txt","r")
    m=1
    print(threadID)
    print(threading.current_thread())
    # print(threadID)
    # print(counter)
    if threadID==1:
        wordlists =wordlist.readlines(counter)
    else:
        wordlists =wordlist.readlines()[counter*(threadID-1):counter*threadID]
    for i in wordlists:
        try:
            bruteUrl=url+i
            bruteRequest=requests.get(bruteUrl)
            print(threading.current_thread())
            bruteStatus=bruteRequest.status_code
            print(str(bruteStatus)+"                     "+bruteUrl)
            if bruteStatus==200:
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = []
                for j in bruteUrl:
                    base = (url,'Directory Opened','Directory is opened due to which there is high probability of information disclosure','Go to '+bruteUrl,'Directory Listing','Medium')
                    val.append(base)
                insert=list(dict.fromkeys(val))
                mycursor.executemany(sql, insert)
                mydb.commit()
        except:
            bruteUrl=url+"/"+i
            bruteRequest=requests.get(bruteUrl)
            bruteStatus=bruteRequest.status_code
            print(str(bruteStatus)+"                     "+bruteUrl)
            if bruteStatus==200:
                sql = "INSERT INTO Vulnerabilities (url,title,description,type,steps,severity) VALUES (%s,%s,%s,%s,%s,%s)"
                val = []
                for j in bruteUrl:
                    base = (url,'Directory Opened','Directory is opened due to which there is high probability of information disclosure','Go to '+bruteUrl,'Directory Listing','Medium')
                    val.append(base)
                insert=list(dict.fromkeys(val))
                mycursor.executemany(sql, insert)
                mydb.commit()
def dirsearchThread():
    wordlistNumber= open("wordlist/wordlist.txt","r")
    t=int(thread)
    number=int(len(wordlistNumber.readlines())/t)
    print(number)
    for i in range(1,t+1):
        myThread(i,"Thread"+str(i),number).start()
#    thread1 = myThread(1, "Thread-1", 500)
#    thread2 = myThread(2, "Thread-2", 1273719)
#    thread1.start()
#    thread2.start()
def hunterApi():
    getUrl=(url.replace('www.','')).replace('https://','')
    getEmail=requests.get("https://api.hunter.io/v2/domain-search?domain="+getUrl+"&api_key=XXXXXXXXXXXXXXXXXX")
    getContent=getEmail.content
    getJson=json.loads(getContent)
    emails=[]
    print("Publicly Accessible Emails:")
    for  i in range(len(getJson['data']['emails'])):
        email=getJson['data']['emails'][i]['value']
        print("\033[31m"+email+"\033[0m")
        os.system('proxychains4 python3 Tor/tor.py'+" "+email+"|sed -n -e '/^1$/,/^61$/p'")
        listEmail=list(email.split(" "))
        emails=emails+listEmail
    #Checking Emails over Tor
def main():
    print("Pwning like you Own it")
    print("\033[31m")
    print("""                ____                              _ _   _     __  __"""+"""
                |  _ \ ___  ___ ___  _ ____      _(_) |_| |__ |  \/  | ___
                | |_) / _ \/ __/ _ \| '_ \ \ /\ / / | __| '_ \| |\/| |/ _ \ """+"""
                |  _ <  __/ (_| (_) | | | \ V  V /| | |_| | | | |  | |  __/
                |_| \_\___|\___\___/|_| |_|\_/\_/ |_|\__|_| |_|_|  |_|\___|

"""+"   \033[0m                                         Welcome to ReconwithMe\n                                    \033[33m                    Coded by @evilboyajay\033[0m")
    print("[-] Scraping the URL's and saving it to JSON file")
    db()
    scrape()
    serverDetails()
    print("   \033[34m              [+] Scraping Successfull \033[0m\n")
    print("[-] Checking Clickjacking Vulnerbility")
    clickjacking()
    print("[-] Checking SQL Injection Vulnerbility")
    sqlinjection()
    print("[-] Checking Javascript Injection Vulnerbility")
    xss()
    openRedirect()
    print("[-] Checking Directory Listing Vulnerbility \n")
    print("Status                      Directory                        Size")
    print("_________                   __________                       _____")
#Directory Bruteforce Using threading
    dirsearchThread()
    hunterApi()
main()
