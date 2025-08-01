#This is a project to get weather info for a city and email it to aaviles@aitworldwide.com
import requests
import geopy.geocoders

# Get city name from user
city = input("Enter a city: ")

#Open-Meteo doesn't support city name queries so we have to convert city to lat and long
geolocator = Nominatim(user_agent="weather-script")
location = geolocator.geocode(city)

if not location:
    print("City not found.")
    exit()

lat = location.latitude
lon = location.longitude

# Step 2: Request daily weather from Open-Meteo
weather_url = "https://api.open-meteo.com/v1/forecast"
params = {
    "latitude": lat,
    "longitude": lon,
    "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum",
    "timezone": "auto"
}

#Make the GET request
response = requests.get(weather_url, params=params)
data = response.json()

# Step 3: Print forecast
print(f"\nDaily forecast for {city.title()}:")
days = data["daily"]["time"]
temps_max = data["daily"]["temperature_2m_max"]
temps_min = data["daily"]["temperature_2m_min"]
rain = data["daily"]["precipitation_sum"]

for i in range(len(days)):
    print(f"{days[i]} → Max: {temps_max[i]}°C, Min: {temps_min[i]}°C, Rain: {rain[i]} mm")