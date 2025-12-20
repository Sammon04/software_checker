import subprocess
import json
import requests
import re
from rapidfuzz import fuzz


def normalize_name(name : str) -> str:

    if name:
        #Remove Versions from display name
        name = re.sub(r'\b\d+(\.\d+)+\b', '', name)

        #Remove things in parentheses from display name
        name = re.sub(r'\([^)]*\)', '', name)

        #Remove ' - ' from display name
        name = re.sub(r'( - )', '', name)

        #Remove architecture signifiers
        name = re.sub(r'(x64|x86|amd64|arm64|aarch64|32[- ]?bit|64[- ]?bit|win32|win64)', ' ', name, flags=re.IGNORECASE)

        #Remove language identifiers
        name = re.sub(r'([a-z]{2}-([a-z]{2}|[A-Z]{2}))', '', name)

        #Normalize case
        name = name.lower()

        #Remove extra spaces
        name = re.sub(r'(\s+)', ' ', name).strip()

    return name

def normalize_vendor(vendor : str) -> str:
    if vendor:
        #Remove publisher tags
        vendor = re.sub(r'\b(inc|llc|ltd)\b', '', vendor, flags=re.IGNORECASE)

        #Remove periods
        vendor = re.sub(r'\.', '', vendor)

        #Remove extra spaces
        vendor = re.sub(r'(\s+)', ' ', vendor).strip()

        #Normalize case
        vendor = vendor.lower()

    return vendor

#Takes json object returned from circle vulerability query and displays relevent information
def print_circl_result(data):
    if data["results"]:
        print("**CVE Details**")
        for sourceName in data["results"]:
            print(f"Source: {sourceName}")

            source = data["results"].get(sourceName)
            cve = source[0]
            print(f"CVE Name: {cve[0]}")

            cve_data = cve[1]
            containers = cve_data.get("containers")
            for containerName in containers:
                container = containers.get(containerName)

                if containerName == "cna" and isinstance(container, dict) and "metrics" in container:
                    print("CNA Description and metrics:")
                    description = container.get("descriptions")
                    metrics = container.get("metrics")

                    print(f"\tDescription: {description[0]["value"]}")
                    print("\tScoring standards:")

                    for standardName in metrics[0]:
                        print(f"\t\tName: {standardName}")
                        standard = metrics[0].get(standardName)

                        if isinstance(standard, dict):
                            print(f"\t\tScore: {standard["baseScore"]}")
                            print(f"\t\tSeverity: {standard["baseSeverity"]}")

                if containerName == "adp" and isinstance(container, list):
                    print("ADP details: ")
                    for item in container:
                        if isinstance(item, dict) and "metrics" in item:
                            metrics = item.get("metrics")
                    try:
                        for tag in metrics[0]["other"]["content"]["options"]:
                            for title, status in tag.items():
                                print(f"\t{title}: {status}")
                    except KeyError as e:
                        print(e)
    else:
        print("No CVEs listed")


#Current: attempts to match a raw vendor name from the registry with a vendor listed in circl's vendor list
def match_vendor(raw_vendor : str, vendors : list, alias_map : dict) -> dict:
    vendor_dict = {}
    norm_vendor = normalize_vendor(raw_vendor)
    if not norm_vendor:
        return vendor_dict

    if norm_vendor in alias_map:
        norm_vendor = alias_map[norm_vendor]

    if norm_vendor in vendors:
        vendor_dict[norm_vendor] = 100
    
    for vendor in vendors:
        ratio = fuzz.ratio(norm_vendor, vendor)
        if ratio >= 90 and vendor not in vendor_dict:
            vendor_dict[vendor] = ratio

    
    return vendor_dict

#Current: attempts to match a raw product name from the registry with a product listed in circl's list of products for a given vendor
def match_product(raw_product : str, products : list, alias_map : dict) -> dict:
    product_dict = {}
    norm_product = normalize_name(raw_product)

    if norm_product in alias_map:
        norm_product = alias_map[norm_product]

    if norm_product in products:
        product_dict[norm_product] = 100
    
    for product in products:
        ratio = fuzz.ratio(norm_product, product)
        if ratio >= 90 and product not in product_dict:
            product_dict[product] = ratio
    
    return product_dict
    
def check_for_vulnerabilities(software_list, circl_vendors, aliases):
    prev_vendors = {}
    print("LOOKING FOR VULNERABILITIES")
    for software in software_list:

        raw_vendor = software["Publisher"]
        raw_product = software["Publisher"]
        vendor_list = match_vendor(raw_vendor, circl_vendors, aliases)

        if vendor_list:
            for vendor, vendor_ratio in vendor_list.items():

                if vendor not in prev_vendors:
                    print(f"Gathering products for {vendor}")
                    r = requests.get(f"https://cve.circl.lu/api/browse/{vendor}")
                    if r.ok:
                        prev_vendors[vendor] = r.json()
                    else:
                        print("CIRCL ERROR")
            
                if vendor in prev_vendors:
                    product_list = match_product(raw_product, prev_vendors[vendor], aliases)
                    if product_list:
                        for product, product_ratio in product_list.items():
                            print('--------------')
                            if vendor_ratio >= 100 and product_ratio >= 100:
                                print("**EXACT MATCH FOUND!**")
                            else:
                                print("**PARTIAL MATCH FOUND**")
                            print(f"Product: {product}")
                            print(f"Vendor: {vendor}")
                            r = requests.get(f"https://cve.circl.lu/api/vulnerability/search/{vendor}/{product}")
                            if r.ok:
                                result = r.json()
                                print_circl_result(result)

                            else:
                                print("CIRCL ERROR")
    

def main():
    #powershell command to gather installed software on the system and return it as a JSON list
    powershell_command = r"""
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $software = foreach ($path in $paths) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue |
                Select-Object DisplayName, Publisher, DisplayVersion
        }
    }

    $software | Where-Object { $_.DisplayName } | ConvertTo-Json
    """

    #Gather installed software on the system
    #Runs the above powershell command
    #----------------------
    try:
        print("Gathering installed software... This may take a moment.")
        result = subprocess.run(["powershell.exe", "-Command", powershell_command], 
                                capture_output=True, 
                                text=True, 
                                check=True)

        if result.stderr:
            print("Powershell Error:")
            print(result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"stderr: {e.stderr}")
    except FileNotFoundError:
        print("ERROR: Powershell not found")

    #Loads the powershell output JSON into a variable
    data = json.loads(result.stdout)

    if isinstance(data, dict):
        data = [data]
    #----------------------

    #List of hard-coded software/vendor aliases
    #----------------------
    aliases = {
        "igor pavlov" : "7-zip",
        "microsoft corporation" : "microsoft",
        "notepad++ team" : "notepad-plus-plus",
        "notepad++" : "notepad-plus-plus"
    }
    #----------------------

    #Gets the list of all software vendors from circl
    print("GATHERING VENDORS")
    r = requests.get(f"https://cve.circl.lu/api/browse/")
    if r.ok:
        circl_vendors = r.json()
    else:
        print("CIRCL ERROR")

    check_for_vulnerabilities(data, circl_vendors, aliases)


if __name__ == "__main__":
    main()