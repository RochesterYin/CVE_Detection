import json

# Read the NVDCVE JSON data
with open('nvdcve-1.1-2022.json', 'r') as json_file:
    nvdcve_data = json.load(json_file)

# Extract CVE descriptions
cve_entries = nvdcve_data.get('CVE_Items', [])

# Define mappings of keywords to Maven coordinates (groupId and artifactId)
keyword_mappings = {
    'Apache': ('org.apache', 'apache'),
    'MySQL': ('mysql', 'mysql-connector-java'),
    'Windows': ('com.microsoft.windows', 'windows-sdk'),
    'Spring': ('org.springframework', 'spring-core'),
    'Tomcat': ('org.apache.tomcat', 'tomcat'),
    'jQuery': ('org.webjars', 'jquery'),
    'React': ('com.facebook.react', 'react'),
    'Linux': ('org.linux', 'linux-library'),
    'Python': ('org.python', 'python-library'),
    'Django': ('org.djangoproject', 'django'),
    'Node.js': ('org.nodejs', 'nodejs'),
    'Ruby on Rails': ('org.rubyonrails', 'rails'),
    'Elasticsearch': ('org.elasticsearch', 'elasticsearch'),
    'Kubernetes': ('io.kubernetes', 'kubernetes-client'),
    'Angular': ('com.angular', 'angular'),
    'Vue.js': ('org.vuejs', 'vue'),
    'PostgreSQL': ('org.postgresql', 'postgresql'),
    'Redis': ('io.redis', 'redis-client'),
}

# Define the output file name
output_file_name = 'pom.xml'

# Create the pom.xml file with CVE descriptions matched to Maven dependencies
with open(output_file_name, 'w') as pom_file:
    pom_file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    pom_file.write('<project xmlns="http://maven.apache.org/POM/4.0.0"\n')
    pom_file.write('         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n')
    pom_file.write('         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">\n')
    pom_file.write('    <modelVersion>4.0.0</modelVersion>\n')
    pom_file.write('\n')
    pom_file.write('    <groupId>your-group-id</groupId>\n')
    pom_file.write('    <artifactId>your-artifact-id</artifactId>\n')
    pom_file.write('    <version>1.0-SNAPSHOT</version>\n')
    pom_file.write('\n')
    pom_file.write('    <dependencies>\n')

    for entry in cve_entries:
        description = entry['cve']['description']['description_data'][0]['value']

        # Search for keywords in the CVE description and find corresponding Maven coordinates
        matched_dependencies = set()
        for keyword, (group_id, artifact_id) in keyword_mappings.items():
            if keyword.lower() in description.lower():
                matched_dependencies.add((group_id, artifact_id))

        # Write matched dependencies to the pom.xml file
        for group_id, artifact_id in matched_dependencies:
            pom_file.write('        <dependency>\n')
            pom_file.write(f'            <groupId>{group_id}</groupId>\n')
            pom_file.write(f'            <artifactId>{artifact_id}</artifactId>\n')
            pom_file.write(f'            <version>1.0.0</version>\n')
            pom_file.write(f'        </dependency>\n')

    pom_file.write('    </dependencies>\n')
    pom_file.write('</project>\n')

print(f"{output_file_name} file has been generated with CVE descriptions matched to Maven dependencies.")
