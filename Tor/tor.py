import requests
import sys
from bs4 import BeautifulSoup
email=str(sys.argv[1])
emailSplit=email.split("@")
emailUsername=emailSplit[0]
emailDomain=emailSplit[1]
headers = {
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'Accept-Language': 'en-US,en;q=0.5',
'Referer': 'http://pwndb2am4tzkvold.onion/',
'Content-Type': 'application/x-www-form-urlencoded',
'Connection': 'keep-alive',
'Upgrade-Insecure-Requests': '1',
}

data = {
  'luser': emailSplit[0],
  'domain': emailSplit[1],
  'luseropr': '0',
  'domainopr': '0',
  'submitform': 'em'
}

response = requests.post('http://pwndb2am4tzkvold.onion/', headers=headers, data=data)
content=response.content
soup=BeautifulSoup(content, 'html.parser')
credential=soup.find_all("pre")
print("\033[31m"+(((str(credential)).replace("&gt;","")).replace("	</pre>]",""))+"\033[0m")
