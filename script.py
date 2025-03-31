import requests
import json

txt_file = "phishing-filter-agh.txt"

api_url = "https://www.virustotal.com/api/v3/urls"

# Get API key from environment variable
api_key = os.getenv("VT_API_KEY")

with open(txt_file) as fp:
    for line in fp:
        if line.startswith("||"):
            url = line.strip().lstrip("||").rstrip("^")
            
            is_malicious = False
        
            headers = {
                "accept":"application/json",
                "content-type": "application/x-www-form-urlencoded",
                "x-apikey": api_key
            }

            form_data = {
                "url": url
            }

            response = requests.post(api_url, headers=headers, data=form_data)

            if response.text:
                parsed_json = json.loads(response.text)

                if 'data' in parsed_json:
                    
                    analysis_link = parsed_json['data']['links']['self']

                    headers = {
                        "accept":"application/json",
                        "x-apikey": api_key
                    }

                    analysis_response = requests.get(analysis_link, headers=headers)

                    if analysis_response.text:

                        analysis_parsed_json = json.loads(analysis_response.text)

                        stats = analysis_parsed_json['data']['attributes']['stats']

                        if stats['malicious']:
                            if stats['malicious'] > 2:
                                is_malicious = True

            if is_malicious:
                print (url, "IS MALICIOUS", stats['malicious'])
            else:
                print (url, "is not malicious")
