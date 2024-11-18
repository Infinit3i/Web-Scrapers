import pandas as pd

# Load the Excel file
input_file = "splunk_detections_filtered.xlsx"  # Change this to your Excel file name
output_file = "formatted_search_queries.txt"  # Output file for the queries
df = pd.read_excel(input_file)

# Open the output file to write the queries
with open(output_file, "w") as f:
    # Iterate through each row in the DataFrame
    for index, row in df.iterrows():
        # Extract the search query and TTP values
        search_query = row.get("Search", "").strip()  # Adjust column name if needed
        ttp = row.get("TTP", "").strip()

        if search_query and ttp:
            # Format the output
            formatted_query = f"{search_query}\n| eval mitreT-code=`{ttp}`\n"
            f.write(formatted_query + "\n")  # Write to the output file
            print(f"Formatted query for index {index} written.")

print(f"Formatted search queries saved to {output_file}.")
