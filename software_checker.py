import subprocess
import json
import requests
import re
from rapidfuzz import fuzz


def normalize_name(name : str) -> str:

    if name:
        name = re.sub(r'\b\d+(\.\d+)+\b', '', name)                     #Remove Versions from display name
        name = re.sub(r'\([^)]*\)', '', name)                           #Remove things in parentheses from display name
        name = re.sub(r'( - )', '', name)                               #Remove ' - ' from display name
        name = re.sub(r'(x64|x86|amd64|arm64|aarch64|32[- ]?bit|64[- ]?bit|win32|win64)', ' ', name, flags=re.IGNORECASE)   #Remove architecture signifiers
        name = re.sub(r'([a-z]{2}-([a-z]{2}|[A-Z]{2}))', '', name)      #Remove language identifiers
        name = name.lower()                                             #Normalize case
        name = re.sub(r'(\s+)', ' ', name).strip()                      #Remove extra spaces
    return name

def normalize_vendor(vendor : str) -> str:

    if vendor:    
        vendor = re.sub(r'\b(inc|llc|ltd)\b', '', vendor, flags=re.IGNORECASE)  #Remove publisher tags
        vendor = re.sub(r'\.', '', vendor)                                      #Remove periods
        vendor = re.sub(r'(\s+)', ' ', vendor).strip()                          #Remove extra spaces
        vendor = vendor.lower()                                                 #Normalize case
    return vendor

def gather_circl_results(data) -> dict:
    result = {}
    if not data["results"]:
        return result
    
    for source_name in data["results"]:
        source_data = data["results"].get(source_name)
        
        for cve in source_data:
            cve_name = cve[0]

            if cve_name not in result:
                result[cve_name] = {}

            result[cve_name][source_name] = {}
            cve_entry = result[cve_name][source_name]

            containers = cve[1].get("containers")
            if not containers:
                continue

            cna = containers.get("cna")
            if not cna:
                continue
            
            title = cna.get("title")
            if title:
                cve_entry["title"] = title
            
            description = cna.get("descriptions")
            if description:
                cve_entry["description"] = description[0]["value"]
            
            affected_data = cna.get("affected")
            if "affected" in cna:
                vendor = affected_data[0]["vendor"]
                product = affected_data[0]["product"]
                version_info = affected_data[0].get("versions")
                cve_entry["affected"] = {}
                affected_results = cve_entry["affected"]

                cve_entry["vendor"] = vendor
                cve_entry["product"] = product
                
                if "versionType" in version_info[0] and version_info[0]["versionType"] == "custom":

                    affected_results["version"] = "<" + version_info[0]["lessThan"]

                elif '<' in version_info[0]["version"]:

                    stripped_version = version_info[0]["version"].replace(" ", "")
                    affected_results["version"] = stripped_version

                else:

                    affected_results["version"] = version_info[0]["version"]

                affected_results["status"] = version_info[0]["status"]

            if "metrics" in cna:
                cve_entry["metrics"] = {}
                metrics = cve_entry["metrics"]

                for key, value in cna["metrics"][0].items():
                    if isinstance(value, dict):

                        metrics["Scoring System"] = key

                        if "baseScore" in value:
                            metrics["baseScore"] = value["baseScore"]

                        if "baseSeverity" in value:
                           metrics["baseSeverity"] = value["baseSeverity"]
    
    return result
    
    

#Takes json object returned from circle vulerability query and displays relevent information
def print_circl_result(data) -> bool:
    if not data["results"]:
        print("No CVEs listed")
        return False
    
    print("**CVE Details**")
    for sourceName in data["results"]:
        print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ")
        print(f"Source: {sourceName}")

        source = data["results"].get(sourceName)
        for cve in source:
            print(f"CVE Name: {cve[0]}")

            cve_data = cve[1]
            containers = cve_data.get("containers")
            for containerName in containers:
                container = containers.get(containerName)

                if containerName == "cna" and isinstance(container, dict):
                    print("CNA:")

                    if "affected" in container:
                        affected = container.get("affected")
                        print("\tAffected:")
                        print(f"\t\tVendor: {affected[0]["vendor"]}")
                        print(f"\t\tProduct: {affected[0]["product"]}")

                        if "versions" in affected[0]:
                            versions = affected[0]["versions"][0]
                            for key, value in versions.items():
                                print(f"\t\t{key}: {value}")

                    if "descriptions" in container:
                        description = container.get("descriptions")
                        print(f"\tDescription: \n\t{description[0]["value"]}")
                    else:
                        print("\tNo Descriptions Found")

                    if "metrics" in container:
                        metrics = container.get("metrics")
                        print("\tScoring standards:")
                    else:
                        print("\tNo Scoring Standards Found")

                    for standardName in metrics[0]:
                        if standardName != "format":
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
            print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    return True


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
        if ratio >= 95 and vendor not in vendor_dict:
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
        if ratio >= 95 and product not in product_dict:
            product_dict[product] = ratio
    
    return product_dict
    
def check_for_vulnerabilities(software_list, circl_vendors, aliases):
    prev_vendors = {}
    print("LOOKING FOR VULNERABILITIES")
    
    for software in software_list:                                          #For every installed program:

        raw_vendor = software["Publisher"]
        raw_product = software["DisplayName"]
        vendor_list = match_vendor(raw_vendor, circl_vendors, aliases)      #Create a dict of matching circl vendors and their similarity ratio

        if not vendor_list:
            continue

        for vendor, vendor_ratio in vendor_list.items():

            if vendor not in prev_vendors:                                  #Gather products for this vendor if we haven't yet
                print(f"Gathering products for {vendor}")
                r = requests.get(f"https://cve.circl.lu/api/browse/{vendor}")
                if r.ok:
                    prev_vendors[vendor] = r.json()
                else:
                    print("CIRCL ERROR")
        
            if vendor not in prev_vendors:                                  #If circl doesn't have that vendor, skip
                continue

            product_list = match_product(raw_product, prev_vendors[vendor], aliases)    #Create a list of matching circl products for that vendor

            if not product_list:
                continue

            for product, product_ratio in product_list.items():

                print('----------------------------')
                if vendor_ratio >= 100 and product_ratio >= 100:
                    print("**EXACT MATCH FOUND!**")
                else:
                    print("*Partial Match Found*")

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