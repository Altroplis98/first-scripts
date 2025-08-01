#This is a project to get information on a country
import requests

# Get country name from user
country = input("Enter a country: ")

#This is the Country API
url = f"https://restcountries.com/v3.1/name/{country}"

#Make the GET request
response = requests.get(url)

#Convert to JSON
data = response.json()

#Get first result
country_info = data[0]

#Extract info
name = country_info["name"]["common"]
capital = country_info["capital"][0]
population = country_info["population"]
area = country_info["area"]
currency = country_info["currencies"]
region = country_info["region"][0]
flag = country_info["flag"][0]

#Print results
print(f"Name: {name}")
print(f"Capital: {capital}")
print(f"Population: {population}")
print(f"Area: {area}")
print(f"Currency: {currency}")
print(f"Region: {region}")
print(f"Flag: {flag}")