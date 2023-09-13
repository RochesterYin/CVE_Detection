import sqlite3
import json

# Function to create the SQLite database
def create_database():
    # Connect to the SQLite database or create it if it doesn't exist
    conn = sqlite3.connect('cve_database.db')
    cursor = conn.cursor()

    # Create a table to store CVE data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_data (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            published_date TEXT,
            last_modified_date TEXT
        )
    ''')

    # Commit changes and close the database connection
    conn.commit()
    conn.close()

# Function to load data from JSON into the database
def load_data_from_json():
    # Connect to the SQLite database
    conn = sqlite3.connect('cve_database.db')
    cursor = conn.cursor()

    # Load data from the JSON file
    with open('/Users/yinxiangrong/Desktop/Academic Resouces/ND Recources/CSE 60770Secure Software Engineering/HW1/nvdcve-1.1-2022.json', 'r') as json_file:
        cve_data = json.load(json_file)

    # Iterate through the JSON data and insert records into the database
    for entry in cve_data['CVE_Items']:
        cve_id = entry['cve']['CVE_data_meta']['ID']
        description = entry['cve']['description']['description_data'][0]['value']
        published_date = entry['publishedDate']
        last_modified_date = entry['lastModifiedDate']

        # Insert data into the cve_data table
        cursor.execute('''
            INSERT INTO cve_data (cve_id, description, published_date, last_modified_date)
            VALUES (?, ?, ?, ?)
        ''', (cve_id, description, published_date, last_modified_date))

    # Commit changes and close the database connection
    conn.commit()
    conn.close()

# Function to retrieve basic statistics about the data
def get_basic_statistics():
    # Connect to the SQLite database
    conn = sqlite3.connect('cve_database.db')
    cursor = conn.cursor()

    # Get the number of CVE entries
    cursor.execute('SELECT COUNT(*) FROM cve_data')
    count = cursor.fetchone()[0]

    # Close the database connection
    conn.close()

    return count

if __name__ == "__main__":
    # Create the database
    create_database()

    # Load data from JSON into the database
    load_data_from_json()

    # Get basic statistics
    total_cve_entries = get_basic_statistics()
    print(f'Total number of CVE entries: {total_cve_entries}')
