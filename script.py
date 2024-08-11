import requests
import json

txt_file = "phishing-filter-agh.txt"

api_url = "https://www.virustotal.com/api/v3/urls"


with open(txt_file) as fp:
    for line in fp:
        if line.startswith("||"):
            url = line.strip().lstrip("||").rstrip("^")
            print(url)
            is_malicious = False
        
            headers = {
                "accept":"application/json",
                "content-type": "application/x-www-form-urlencoded",
                "x-apikey": "a39b0d386609a77dae047e18ce4a2bb48218d64db112adb3502f624ca2146624"
            }

            form_data = {
                "url": url
            }

            response = requests.post(api_url, headers=headers, data=form_data)

            if response.text:
                parsed_json = json.loads(response.text)
                
                analysis_link = parsed_json['data']['links']['self']

                headers = {
                    "accept":"application/json",
                    "x-apikey": "a39b0d386609a77dae047e18ce4a2bb48218d64db112adb3502f624ca2146624"
                }

                analysis_response = requests.get(analysis_link, headers=headers)

                if analysis_response.text:

                    analysis_parsed_json = json.loads(analysis_response.text)

                    stats = analysis_parsed_json['data']['attributes']['stats']

                    print(stats)

                    if stats['malicious']:
                        if stats['malicious'] > 2:
                            is_malicious = True

            if is_malicious:
                print ("IS MALICIOUS")
            else:
                print ("is not malicious")
            print()