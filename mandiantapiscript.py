import base64
import requests
import json

bearer_token = None

#please go through this link to get better understanding on editing params and usage https://docs.mandiant.com/home/mati-threat-intelligence-api-v4#tag/Vulnerabilities
def get_bearer():
    url = "https://api.intelligence.mandiant.com/token"
    api_key = "b1fccd6bf68ceb21bbb35bff2b2d1ace926a2d2d616891c8e81ba37e7c2aec41"
    api_secret = "b4a6f8fa0520f940a071a7bd38fd184117a5f3d8e44d10953e566b1450667a48"
    auth_token_bytes = f"{api_key}:{api_secret}".encode("ascii")
    base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
    base64_auth_token = base64_auth_token_bytes.decode("ascii")
    headers = {
        "Authorization": f"Basic {base64_auth_token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "X-App-Name": "insert app name"
    }
    print(base64_auth_token)
    params = {"grant_type": "client_credentials"}
    access_token = requests.post(url=url, headers=headers, data=params)
    # print(access_token.json().get("access_token"))
    global bearer_token
    bearer_token = str(access_token.json().get("access_token"))
    print(bearer_token)
    return {"bearer_token": str(access_token.json().get("access_token"))}


# global bearer_token
# bearer_token = "b96bed6bcd5698a1493496f990eacee6d3fa426d35ed12845e296b39cf828cb2"e4f514b8809aed51780ace51ad323ebf0157eb04c6164cca19fc9decd7c51d39
def List_Vulnerabilies():
    url = "https://api.intelligence.mandiant.com/v4/vulnerability"
    #bearer_token = "1c7918b8b04913eaebcfb4724e4499c7457b5a156b5560355ea0994e2f066978"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = {"start_epoch":"1751376912"}#"ids":"CVE-2023-21247,CVE-2023-21202" , exploitation_filters=was_zero_day,cisa_known_exploited, was_zero_day=true
    # #"risk_ratings":"HIGH", exploitation_states=Wide,Confirmed, exploitation_consequences=Code Execution,Information Disclosure,
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

#List_Vulnerabilies()

def Cve_Vulnerabilities():
    import requests
    import json
    url = "https://api.intelligence.mandiant.com/v4/vulnerability"
    #bearer_token = "insert bearer token"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
        "Content-Type": "application/json",
    }
    post_body = {"requests": [{"values": ["CVE-2019-10149", "CVE-2023-21247"]}]}
    params = {}
    resp = requests.post(url=url, headers=headers, data=json.dumps(post_body))
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

#Cve_Vulnerabilities()

def List_Vulnerabilies_filter():
    url = "https://api.intelligence.mandiant.com/v4/vulnerability"
    #bearer_token = "1c7918b8b04913eaebcfb4724e4499c7457b5a156b5560355ea0994e2f066978"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = {"has_cve": True, "risk_ratings": "CRITICAL"}
    output_filename = "C:\\Users\\RohithRonanki\\Desktop\\vulnerabilities_data.json"

    print(f"[*] Attempting to fetch data from {url}...")
    try:
        resp = requests.get(url=url, headers=headers, params=params)
        resp.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        data_from_api = resp.json()
        print("\n--- API Response JSON: ---")
        print(json.dumps(data_from_api, indent=4))
        print("--------------------------")

        # Save the JSON data directly to a file
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(data_from_api, f, indent=4)
        print(f"\n[+] Successfully saved API response to '{output_filename}'")

    except requests.exceptions.RequestException as e:
        # Catch all requests-related errors (ConnectionError, HTTPError, Timeout, etc.)
        print(f"[-] Request Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"[-] Response status code: {e.response.status_code}")
            print(f"[-] Response content: {e.response.text}")
    except json.JSONDecodeError as e:
        print(f"[-] Error decoding JSON response: {e}")
        if 'resp' in locals():
            print(f"[-] Raw response content was: {resp.text[:500]}...")
    except IOError as e:
        print(f"[-] Error saving file '{output_filename}': {e}")


def Vulnerability_by_cveid():
    url = "https://api.intelligence.mandiant.com/v4/vulnerability/CVE-2023-21247" # change cve_id
    # bearer_token = "insert bearer token"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
    }
    params = {"fields":"vulnUpdate24Q1"} #fields=mve_id,cve_id,risk_rating,vulnUpdate24Q1
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Vulnerability_associated_malware():
    url = "https://api.intelligence.mandiant.com/v4/vulnerability/CVE-2017-0144/malware" # change cve_id
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
    }
    params = {"rating_types": "predicted"}
    #params = None #rating_types=predicted,unrated or None
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Vulnerability_associated_threatactors():
    url = "https://api.intelligence.mandiant.com/v4/vulnerability/CVE-2023-21247/actors" # change cve_id
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
    }
    params = None #rating_types=predicted,unrated or None
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def List_Reports():
    url = "https://api.intelligence.mandiant.com/v4/reports"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = {
        "limit": 1000,
        "offset": 0
    } #start_epoch=1653426342
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Getreport_by_id():
    url = "https://api.intelligence.mandiant.com/v4/report/25-10046250"  # change {report_id}
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = None
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Search_Intelligence():
    url = "https://api.intelligence.mandiant.com/v4/search"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
        "Content-Type": "application/json"
    }
    post_body = {
        "search": "CVE-2023-21247", #search term
        "type": "all", #"all" "indicator" "malware" "report" "threat-actor" "vulnerability"
        "limit": 50,
        "sort_by": [
            "relevance"
        ],
        "sort_order": "asc",
        "next": ""
    }
    params = None
    resp = requests.post(url=url, headers=headers, data=json.dumps(post_body))
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def List_Threatactors():
    url = "https://api.intelligence.mandiant.com/v4/actor"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = {
        "limit": 1000,
        "offset": 0
    }
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Get_Threatactor():
    url = "https://api.intelligence.mandiant.com/v4/actor/threat-actor--0ac5c1db-8ad6-54b8-b4b9-c32fc738c54a" #change {id_or_name}
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = None
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def List_Malwares():
    url = "https://api.intelligence.mandiant.com/v4/malware"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = {
        "limit": 1000,
        "offset": 0
    }
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

def Get_malwarebyid():
    url = "https://api.intelligence.mandiant.com/v4/malware/malware--4ad156ae-83be-5c4a-86ef-60ad7864ea85" # change {id_or_name}
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name"
    }
    params = None
    resp = requests.get(url=url, headers=headers, params=params)
    print(json.dumps(resp.json(), indent=True))
    return json.dumps(resp.json(), indent=True)

if __name__ == "__main__":
    get_bearer()
    #Get_malwarebyid()
    #List_Malwares()
    #Get_Threatactor()
    #List_Threatactors()
    #Search_Intelligence()
    #List_Reports()
    #Getreport_by_id()
    #Vulnerability_associated_malware()
    #Cve_Vulnerabilities()
    # List_Vulnerabilies()
    #Vulnerability_by_cveid()
    #Vulnerability_associated_threatactors()
    # print(bearer_token)
