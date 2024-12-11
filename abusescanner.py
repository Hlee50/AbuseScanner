import requests;

# Method to query URLhaus API for URL information using URL parameter
def scan_url(url):
    data = {'url' : url}
    response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data).json()
    status = response["query_status"]
    print("\nURLhaus:")
    match status:
        case "invalid_url":
            print("Invalid URL, make sure the full URL includes http:// or https://")
        case "no_results":
            print("URL not found")
        case "ok":
            print("URL:", response["url"])
            print("Host:", response["host"])
            print("URL Status:", response["url_status"])
            print("Threat:", response["threat"])
            print("Date Added:", response["date_added"])
            print("Last Online:", response["last_online"])

# Method to query URLhaus API for payload (malware sample) information using file hash parameter
def scan_payload(hash, type):
    data = {type : hash}
    response = requests.post("https://urlhaus-api.abuse.ch/v1/payload/", data).json()
    status = response["query_status"]
    print("\nURLhaus:")
    match status:
        case "invalid_md5_hash":
            print("Invalid MD5 hash")
        case "invalid_sha256_hash":
            print("Invalid SHA256 hash")
        case "no_results":
            print("Hash not found")
        case "ok":
            print("File Type: " + str(response["file_type"]))
            print("File Size: " + str(response["file_size"]) + " bytes")
            print("Malware Family: " + str(response["signature"]))
            print("First Seen: " + str(response["firstseen"]))
            print("Last Seen: " + str(response["lastseen"]))

# Method to query ThreatFox API for IOC information using URL parameter
def scan_ioc(ioc):
    data = {"query" : "search_ioc", "search_term" : ioc}
    response = requests.post("https://threatfox-api.abuse.ch/api/v1/", json = data).json()
    status = response["query_status"]
    print("\nThreatFox:")
    match status:
        case "illegal_search_term":
            print("Invalid URL")
        case "no_result":
            print("URL not found")
        case "ok":
            info = response["data"][0]
            print("IOC:", info["ioc"])
            print("Threat Type:", info["threat_type"])
            print("Threat Type Description:", info["threat_type_desc"])
            print("IOC Type:", info["ioc_type"])
            print("IOC Type Description:", info["ioc_type_desc"])
            print("Malware:", info["malware_printable"])
            print("Confidence Level:", info["confidence_level"])
            print("First Seen:", info["first_seen"])
            print("Last Seen:", info["last_seen"])

# Method to query MalwareBazaar API for malware sample information using file hash parameter
def scan_malware(hash):
    data = {"query" : "get_info", "hash" : hash}
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data).json()
    status = response["query_status"]
    print("\nMalware Bazaar:")
    match status:
        case "illegal_hash":
            print("Invalid hash")
        case "hash_not_found":
            print("Hash not found")
        case "ok":
            info = response["data"][0]
            print("File Name:", info["file_name"])
            print("File Size:", info["file_size"], "bytes")
            print("File Type:",  info["file_type"])
            print("Origin Country:", info["origin_country"])
            print("Malware Family:", info["signature"])
            print("First Seen:", info["first_seen"])
            print("Last Seen:", info["last_seen"])


# Script
if __name__ == "__main__":
    print("Select an option to scan for reported malicious URLs or filehashes by querying from Abuse.ch databases (URLhaus, ThreatFox, and MalwareBazaar)")
    # Main loop to prompt user for URL or file hash input(s) after selecting the appropriate option from the list of options
    while True:
        print("\n1: Scan URL\n" + "2: Scan Filehash\n" + "/e: Exit\n")
        print("> ", end='')
        option = input()
        match option:
            case "1": # URL input
                print("\nEnter the URL")
                print("> ", end='')
                url = input()
                scan_url(url)
                scan_ioc(url)
            case "2": # File hash input
                print("\nSelect the type of filehash\n1: Scan MD5\n2: Scan SHA256\n")
                print("> ", end='')
                hashtype = input()
                match hashtype:
                    case "1":
                        print("\nEnter the MD5 filehash")
                        print("> ", end='')
                        hash = input()
                        scan_payload(hash, "md5_hash")
                        scan_malware(hash)
                    case "2":
                        print("\nEnter the SHA256 filehash")
                        print("> ", end='')
                        hash = input()
                        scan_payload(hash, "sha256_hash")
                        scan_malware(hash)
                    case _:
                        print("Hash type not avaiable please select one of the available hash types")
            case "/e": # Breaks the infinite loop and exits the script
                print("\nExiting")
                break
            case _:
                print("Option not avaiable please select one of the available options below")
        print("\n")