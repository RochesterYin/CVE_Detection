import sqlite3
import xml.etree.ElementTree as ET
import argparse
import json

# Function to detect vulnerabilities based on loaded dependencies
def detect_vulnerabilities(dependencies):
    vulnerabilities = []
    conn = sqlite3.connect('cve_database.db')
    cursor = conn.cursor()

    for dependency in dependencies:
        group_id, artifact_id, version = dependency
        cursor.execute('''
            SELECT cve_id, description FROM cve_data
            WHERE description LIKE ?
        ''', ('%' + f'{group_id}:{artifact_id}:{version}' + '%',))

        results = cursor.fetchall()
        if results:
            for cve_id, description in results:
                vulnerabilities.append({
                    'CVE ID': cve_id,
                    'Description': description,
                    'Affected Dependency': f'{group_id}:{artifact_id}:{version}'
                })

    conn.close()
    return vulnerabilities

# Function to parse dependencies from a POM file
def parse_pom_file(pom_path):
    dependencies = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Assuming the POM file follows the Maven structure
        for dependency in root.findall('.//dependencies/dependency'):
            group_id = dependency.find('groupId').text
            artifact_id = dependency.find('artifactId').text
            version = dependency.find('version').text
            dependencies.append((group_id, artifact_id, version))

    except ET.ParseError:
        print("Error parsing the POM file.")
    return dependencies

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerable Dependency Finder")
    parser.add_argument("mode", choices=["detectOnly", "doAll"], help="Execution mode")
    parser.add_argument("pom_path", help="Path to the POM file")
    args = parser.parse_args()

    # Load dependencies from the POM file
    dependencies = parse_pom_file(args.pom_path)

    # Detect vulnerabilities based on the loaded dependencies
    vulnerabilities = detect_vulnerabilities(dependencies)

    # Display detected vulnerabilities
    if vulnerabilities:
        print("Detected Vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(f"CVE ID: {vulnerability['CVE ID']}")
            print(f"Description: {vulnerability['Description']}")
            print(f"Affected Dependency: {vulnerability['Affected Dependency']}\n")
    else:
        print("No vulnerabilities detected.")
