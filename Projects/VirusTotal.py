#This project is to send artifacts to Virustotal and get an analysis on their suspicious levels.
import requests

#NEED TO REMOVE THIS AT SOME POINT
API_KEY = "d89614304b5dc734c2de1b0843753f5241a0f531a1760bf9624d152bbfd235a0"

#Ask user what the artifact is such as has, domain, url, or IP
artifacttype = input("What is the type of artifact you are looking for? Ex: hash, domain, url, IP\n")

#Ask the user to provide the artifact
artifact = input("Please enter the artifact you are looking for: \n")

if artifacttype == "hash":
    url = f"https://www.virustotal.com/api/v3/files/{artifact}"
elif artifacttype == "url":
    url = f"https://www.virustotal.com/api/v3/urls/{artifact}"
elif artifacttype == "domain":
    url = f"https://www.virustotal.com/api/v3/domains/{artifact}"
elif artifacttype == "IP":
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{artifact}"
else:
    print("Unsupported artifact type.")
    url = None

headers = {"x-apikey": API_KEY}

response = requests.get(url, headers=headers)
data = response.json()

print(data["data"]["attributes"]["last_analysis_stats"])