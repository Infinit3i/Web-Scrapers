import requests
from bs4 import BeautifulSoup
import pandas as pd

# URL of the webpage to scrape
url = "https://research.splunk.com/detections/"

print("Fetching the main webpage...")
# Send a GET request to the webpage
response = requests.get(url)
if response.status_code != 200:
    print(f"Failed to fetch webpage: {response.status_code}")
    exit()

print("Parsing the HTML content...")
# Parse the HTML content using BeautifulSoup
soup = BeautifulSoup(response.content, "html.parser")

print("Finding all rows in the table...")
# Find all rows in the table
rows = soup.find_all("tr", class_="row")

# Data list to store the parsed content
data = []

# Loop through each row and extract required information
for row in rows:
    # Extract columns
    cols = row.find_all("td")
    
    # Extract individual fields
    detection_link = cols[0].find("a")["href"]
    detection_name = cols[0].get_text(strip=True)
    ttp = cols[2].get_text(strip=True)
    detection_date = cols[5].get_text(strip=True)
    source = cols[1].get_text(strip=True)

    # Filter by source (if needed)
    if "Sysmon" in source or "Windows Event Log" in source:
        print(f"Processing detection: {detection_name}")
        # Visit the detection link
        try:
            detection_page = requests.get(f"https://research.splunk.com{detection_link}")
            detection_page.raise_for_status()
            detection_soup = BeautifulSoup(detection_page.content, "html.parser")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching detection page for {detection_name}: {e}")
            continue

        # Extract technique and tactic specifically from the mitre-table on subpage
        techniques = []
        tactics = []
        mitre_section = detection_soup.find("div", class_="framework-section mitre-attack active")
        if mitre_section:
            mitre_table = mitre_section.find("table", class_="mitre-table")
            if mitre_table:
                rows_mitre = mitre_table.find("tbody").find_all("tr")
                for row_mitre in rows_mitre:
                    try:
                        technique_cell = row_mitre.find_all("td")[1].get_text(strip=True)  # Get the second <td> (Technique)
                        tactic_cell = row_mitre.find_all("td")[2].get_text(strip=True)  # Get the third <td> (Tactic)
                        if technique_cell and tactic_cell:
                            techniques.append(technique_cell)
                            tactics.append(tactic_cell)
                    except (AttributeError, IndexError):
                        print(f"Could not extract technique/tactic from mitre-table for {detection_name}")
                        continue

        # Combine techniques and tactics into a single string
        techniques_str = ', '.join(techniques)
        tactics_str = ', '.join(tactics)

        # Extract the search query (if needed)
        search_code = detection_soup.find("code", class_="language-mysql")
        search = search_code.get_text(strip=True) if search_code else None
        if search:
            print(f"Found search query for {detection_name}")

        # Extract APTs (if needed)
        apt_tags = detection_soup.find_all("div", class_="pill threat-actor")
        apts = ', '.join([apt.get_text(strip=True) for apt in apt_tags])
        if apts:
            print(f"Found APTs for {detection_name}")

        # Append to data list
        data.append({
            "Detection Name": detection_name,
            "Detection Link": f"https://research.splunk.com{detection_link}",
            "TTP": ttp,
            "Date": detection_date,
            "Search": search,
            "Techniques": techniques_str,
            "Tactics": tactics_str,
            "APTs": apts
        })

# Convert data to a pandas DataFrame
df = pd.DataFrame(data)

# Save the data to an Excel file
output_file = "splunk_detections_filtered.xlsx"
df.to_excel(output_file, index=False)

print(f"Filtered data has been successfully saved to {output_file}")

