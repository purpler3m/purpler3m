import requests
import pathlib
import base64
import argparse

# VirusTotal API key
key = ''

#Argparse tool to give a path as an argument instead of entering the path within the program

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--filepath", help="input file that contains a list of URLs", required=True)
args = argParser.parse_args()


def main():
    def vt_url_check():

# Open the file given as an commandline argument and read each line. This will create a list of each line in the document
        with open(args.input, 'r') as f:
            domains = f.readlines()

# Iterate through the list of URLs via a "for" Loop from the text file and remove of any whitespace before or after each word
        for url in urls:
            url = url.strip()
# need to get the URL id from each url, based on VirusTotal Documentation it needs to be the base64 hash encoded without "="
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# Submit URLs to VirusTotal via Get
            headers = {'Accept': 'application/json', 'x-apikey': key}
            response = requests.get('https://www.virustotal.com/api/v3/urls/'+url_id, headers=headers)

# Store the get response in JSON format
            json_response = response.json()
            print(json_response)

# Print interested fiedls from the JSON response
            print("*" * 50)
            print(f"URL: {url}")
            print(response.json()['data']['attributes']['last_final_url'])
            print("*" * 50)
            stats = (response.json()['data']['attributes']['last_analysis_stats'].items())
            print(f"AV Detection statistics: ")
            for stat in stats:
                print(f"{stat}")
            view = response.json()['data']['attributes']['last_analysis_results'].items()
            for result in view:
                for malicious in result:
                    continue
                if 'malicious' in malicious['category']:
                    print(f"Detected MALICIOUS by: {malicious['engine_name']}")

    vt_url_check()

if __name__ == "__main__":
    main()
