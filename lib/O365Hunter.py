import json
import sqlite3
import tempfile
import os
import time
import pandas as pd
import geoip2.database
import requests
from dateutil import parser, tz
import pandas as pd
import json
import csv
from pathlib import Path

password_spray_query = '''
        WITH FailedLogins AS (

    SELECT 
        UserId,
         ClientIP,
        datetime(CreationTime) AS LoginDate
    FROM 
        events
    WHERE 
        Operation = 'UserLoginFailed'

)
SELECT 
    UserId,
    GROUP_CONCAT(ClientIP, ', ') AS ClientIPs,
    COUNT(DISTINCT ClientIP) AS UniqueIPCount,
    COUNT(*) AS FailedLoginAttempts,
    LoginDate

FROM 
    FailedLogins
GROUP BY 
    UserId, 
   strftime('%Y-%m-%d %H', LoginDate)
HAVING 
    COUNT(*) > 5 AND UniqueIPCount > 3
ORDER BY 
    FailedLoginAttempts DESC;
        '''

user_logon_query = '''
SELECT 
    UserId,
    date(CreationTime) AS LoginDate,
    COUNT(*) AS TotalLoginAttempts,
    SUM(CASE WHEN Operation = 'UserLoggedIn' THEN 1 ELSE 0 END) AS SuccessfulLogins,
    SUM(CASE WHEN ResultStatus = 'UserLoginFailed' THEN 1 ELSE 0 END) AS FailedLogins
    FROM 
        events
    where 
    Operation = 'UserLoggedIn' OR Operation = 'UserLoginFailed'
    GROUP BY 
        UserId, 
        LoginDate
    ORDER BY 
        LoginDate, 
        UserId;
'''

def convert_csv(input_file,temp):
    with open(input_file, 'r', encoding='utf-8') as csv_file:
        # Create a CSV reader
        reader = csv.DictReader(csv_file)

        json_file =  'audit_data3.json'
        json_file=os.path.join(temp, json_file)
        with open(json_file, 'w', encoding='utf-8') as jsonl_file:
            # Extract and write the AuditData column to a file as JSON Lines
            for row in reader:
                # Extract the AuditData which is already a JSON formatted string
                json_data = json.loads(row['AuditData'])
                # Convert the JSON object back to a string to store in the file
                json_string = json.dumps(json_data)
                # Write the JSON string to the file with a newline
                jsonl_file.write(json_string + '\n')

    return json_file

def flatten_json_file(input_file, timezone, chunk_size=10000):
    # Read the JSON file in chunks
    chunks = []
    with open(input_file, 'r') as file:
        lines = file.readlines()
        for i in range(0, len(lines), chunk_size):
            chunk = [json.loads(line) for line in lines[i:i + chunk_size]]

            # Convert the CreationTime to the desired timezone
            for record in chunk:
                if 'CreationTime' in record:
                    # Parse the CreationTime, convert to the provided timezone, and format
                    creation_time = parser.parse(record['CreationTime'])
                    record['CreationTime'] = creation_time.astimezone(timezone).isoformat()

            chunks.append(pd.json_normalize(chunk))

    # Concatenate all chunks into a single DataFrame
    flattened_records = pd.concat(chunks, ignore_index=True)

    return flattened_records


def create_sqlite_db_from_dataframe(dataframe, db_name):
    conn = sqlite3.connect(db_name)

    # Convert all columns to string
    dataframe = dataframe.astype(str)

    # Write the DataFrame to SQLite, treating all fields as text
    dataframe.to_sql('events', conn, if_exists='replace', index=False,
                     dtype={col_name: 'TEXT' for col_name in dataframe.columns})

    conn.close()


def read_detection_rules(rule_file):
    with open(rule_file, 'r') as file:
        rules = json.load(file)
    return rules


def apply_detection_logic_sqlite(db_name, rules):
    conn = sqlite3.connect(db_name)
    all_detected_events = []

    for rule in rules:
        rule_name = rule['name']
        severity = rule['severity']
        query = rule['query']

        detected_events = pd.read_sql_query(query, conn)
        detected_events['RuleName'] = rule_name
        detected_events['Severity'] = severity

        all_detected_events.append(detected_events)

    conn.close()

    if all_detected_events:
        result = pd.concat(all_detected_events, ignore_index=True)
    else:
        result = pd.DataFrame()

    return result

def download_geolite_db(geolite_db_path):
    url = "https://git.io/GeoLite2-Country.mmdb"
    print(f"Downloading GeoLite2 database from {url}...")
    response = requests.get(url)
    response.raise_for_status()  # Check if the download was successful

    with open(geolite_db_path, 'wb') as file:
        file.write(response.content)
    print(f"GeoLite2 database downloaded and saved to {geolite_db_path}")

def get_country_from_ip(ip, reader):
    try:
        response = reader.country(ip)
        return response.country.name
    except Exception as e:
        #print(f"Could not resolve IP {ip}: {e}")
        return 'Unknown'


def analyzeoff365(auditfile, rule_file, output, timezone, include_flattened_data=False,
                  geolite_db_path='GeoLite2-Country.mmdb'):
    temp_dir = ".temp"

    try:
        # Create necessary directories
        os.makedirs(output, exist_ok=True)
        os.makedirs(temp_dir, exist_ok=True)

        # Check if the GeoLite2 database exists, and download it if not
        if not os.path.exists(geolite_db_path):
            download_geolite_db(geolite_db_path)

        # Convert CSV to JSON (assuming convert_csv is a valid function that you have)
        json_file = convert_csv(auditfile, temp_dir)

        # Input and output file paths
        input_file = json_file
        db_name = os.path.join(temp_dir, 'audit_data.db')

        if rule_file is None:
            rule_file = 'lib/O365_detection_rules.json'
        output_file = f"{output}_o365_report.xlsx"

        # Measure the start time
        start_time = time.time()

        # Flatten the JSON file
        flattened_df = flatten_json_file(input_file, timezone)

        # Create SQLite database from the flattened DataFrame
        create_sqlite_db_from_dataframe(flattened_df, db_name)

        # Open the GeoLite2 database
        with geoip2.database.Reader(geolite_db_path) as reader:
            # Resolve ClientIP to country names
            if 'ClientIP' in flattened_df.columns:
                flattened_df['Country'] = flattened_df['ClientIP'].apply(lambda ip: get_country_from_ip(ip, reader))

        # Read detection rules
        rules = read_detection_rules(rule_file)

        # Apply detection logic using SQLite
        detected_events = apply_detection_logic_sqlite(db_name, rules)

        # Reorder columns to make RuleName the first column
        if not detected_events.empty:
            columns = ['RuleName', 'Severity'] + [col for col in detected_events.columns if
                                                  col not in ['RuleName', 'Severity']]
            detected_events = detected_events[columns]

        # Perform the brute-force detection query
        conn = sqlite3.connect(db_name)

        try:
            user_login_tracker_df = pd.read_sql_query(user_logon_query, conn)
            password_spray_df = pd.read_sql_query(password_spray_query, conn)
        finally:
            conn.close()

        # Create a new workbook with the detection results
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            if include_flattened_data:
                # Split the flattened data into multiple sheets if needed
                max_rows_per_sheet = 65000
                num_sheets = len(flattened_df) // max_rows_per_sheet + 1

                for i in range(num_sheets):
                    start_row = i * max_rows_per_sheet
                    end_row = (i + 1) * max_rows_per_sheet
                    sheet_name = f'Flattened Data {i + 1}'
                    flattened_df.iloc[start_row:end_row].to_excel(writer, sheet_name=sheet_name, index=False)

            # Write statistics for various fields
            detected_events.to_excel(writer, sheet_name='Detection Results', index=False)
            user_login_tracker_df.to_excel(writer, sheet_name='User Login Tracker', index=False)
            password_spray_df.to_excel(writer, sheet_name='Password Spray Attacks', index=False)
            flattened_df['Operation'].value_counts().to_frame().to_excel(writer, sheet_name='Operation Stats')
            flattened_df['ClientIP'].value_counts().to_frame().to_excel(writer, sheet_name='ClientIP Stats')
            flattened_df['Country'].value_counts().to_frame().to_excel(writer, sheet_name='Country Stats')
            flattened_df['UserAgent'].value_counts().to_frame().to_excel(writer, sheet_name='UserAgent Stats')
            flattened_df['UserId'].value_counts().to_frame().to_excel(writer, sheet_name='UserId Stats')
            flattened_df['AuthenticationType'].value_counts().to_frame().to_excel(writer,
                                                                                  sheet_name='AuthenticationType Stats')

        # Measure the end time
        end_time = time.time()
        print(f"Office365 analysis finished in time: {end_time - start_time:.2f} seconds")

    except Exception as e:
        print(f"An error occurred during the analysis: {e}")

    finally:
        # Clean up the temporary directory
        if os.path.exists(temp_dir):
            for file in Path(temp_dir).glob('*'):
                file.unlink()  # Delete the file
            os.rmdir(temp_dir)  # Remove the directory

        # Write the User Login Tracker results to a new sheet

    # Measure the end time
    end_time = time.time()

    # Calculate and print the running time
    running_time = end_time - start_time
    print(f"Office365 hunter finished in time: {running_time:.2f} seconds")
