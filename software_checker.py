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

def gather_circl_results(data, installed_version) -> dict:
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
            if not affected_data:
                continue

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

            if not match_version(installed_version, affected_results["version"]):
                del result[cve_name][source_name]
                continue

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
        
    remove_list = []
    for cve, data in result.items():
        if not data:
            remove_list.append(cve)
    
    for cve in remove_list:
        del result[cve]
    
    return result


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

def match_version(installed_version : str, affected_version : str) -> bool:
    less_than = True if "<" in affected_version else False
    stripped_installed = re.sub(r'\D', '', installed_version)
    stripped_affected = re.sub(r'\D', '', affected_version)

    try:
        installed_int = int(stripped_installed)
        affected_int = int(stripped_affected)
    except ValueError:
        return False
    
    if less_than and installed_int < affected_int:
        return True
    elif not less_than and installed_int == affected_int:
        return True
    else:
        return False
        


    
def gather_circl_vulnerabilities(software_list, circl_vendors, aliases):
    prev_vendors = {}
    final_result = {}
    print("Checking Circl Database for Vulnerabilities")
    
    for software in software_list:                                          #For every installed program:

        raw_vendor = software["Publisher"]
        raw_product = software["DisplayName"]
        raw_version = software["DisplayVersion"]
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
                
                r = requests.get(f"https://cve.circl.lu/api/vulnerability/search/{vendor}/{product}")
                if not r.ok:
                    print("CIRCL ERROR")
                    continue

                circl_response = r.json()
                cve_details = gather_circl_results(circl_response, raw_version)

                if not cve_details:
                    continue

                final_result[product] = {}
                final_result[product]["Vendor Confidence"] = vendor_ratio
                final_result[product]["Product Confidence"] = product_ratio
                final_result[product]["CVE's"] = cve_details

                print('----------------------------')
                if vendor_ratio >= 100 and product_ratio >= 100:
                    print("**EXACT MATCH FOUND!**")
                else:
                    print("*Partial Match Found*")

                print(f"Product: {product}")
                print(f"Vendor: {vendor}")


        
    with open("testoutput.json", "w") as f:
        json.dump(final_result, f, indent=4)


def main():
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
    

    installed_software = json.loads(result.stdout)

    if isinstance(installed_software, dict):
        installed_software = [installed_software]
    
    with open("installed_software.json", "w") as f:
        json.dump(installed_software, f, indent=4)

    aliases = {
        "igor pavlov" : "7-zip",
        "microsoft corporation" : "microsoft",
        "notepad++ team" : "notepad-plus-plus",
        "notepad++" : "notepad-plus-plus"
    }

    print("GATHERING VENDORS")
    r = requests.get(f"https://cve.circl.lu/api/browse/")
    if r.ok:
        circl_vendors = r.json()
    else:
        print("CIRCL ERROR")

    gather_circl_vulnerabilities(installed_software, circl_vendors, aliases)


if __name__ == "__main__":
    main()