import requests, pathlib, argparse

# VirusTotal API key
key = ''

argParser = argparse.ArgumentParser()
argParser.add_argument("-f", "--filepath", help="input file that contains a list of domains", required=True)
args = argParser.parse_args()

def main():
    def vt_domain():

# Read Domains from text file.
# Open the file given as an argument and read each sentence line. This will create a list of each line in the document
        with open(args.input, 'r') as f:
            domains = f.readlines()

# Iterate through the list of domains via a "for" Loop from the text file and remove whitespace before or after each word
        for domain in domains:
            domain = domain.strip()

# Submit Domain to VirusTotal via Get
            headers = {'Accept': 'application/json', 'x-apikey': key}
            response = requests.get('https://www.virustotal.com/api/v3/domains/'+domain, headers=headers)
# Store the get response in JSON format
            json_response = response.json()

# Print interested fiedls from the JSON response
            print("*" * 50)
            print(f"Domain: {domain}")
            print(response.json()['data']['attributes']['whois'])
            print("*" * 50)
            stats = (response.json()['data']['attributes']['last_analysis_stats'].items())
            print(f"AV Detection statistics: ")
            for stat in stats:
                print(f"{stat}")
            analysis_results = response.json()['data']['attributes']['last_analysis_results'].items()
            for result in analysis_result:
                for malicious in result:
                    continue
                if 'malicious' in malicious['category']:
                    print(f"Detected MALICIOUS by: {malicious['engine_name']}")

    vt_domain()

if __name__ == "__main__":
    main()
