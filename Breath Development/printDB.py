import sqlite3
import logging
import csv
from datetime import datetime

current_datetime = datetime.now()
date_string = current_datetime.strftime('%Y-%m-%d')
time_string = current_datetime.strftime('%H-%M-%S')

logging.basicConfig(filename=f'errors/logs/database{date_string}{time_string}.log', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def printDatabase():
    try:
        db_file = 'database.db'

        # Create a connection to the database file.
        connection = sqlite3.connect(db_file)

        # Create a cursor object to execute SQL queries.
        cursor = connection.cursor()
        
        # Create a CSV file for output.
        output_file = 'database.csv'

        # Open the CSV file for writing.
        with open(output_file, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)

            # Export data from the 'projects' table.
            cursor.execute("SELECT * FROM projects")
            project_rows = cursor.fetchall()

            # Write the header row for the 'projects' table.
            cursor.execute("PRAGMA table_info(projects)")
            project_header = [row[1] for row in cursor.fetchall()]
            csv_writer.writerow(project_header)

            # Write the data rows for the 'projects' table.
            csv_writer.writerows(project_rows)

            # Export data from the 'users' table.
            cursor.execute("SELECT * FROM users")
            user_rows = cursor.fetchall()

            # Write a separator line between the tables.
            csv_writer.writerow([])

            # Write the header row for the 'users' table.
            cursor.execute("PRAGMA table_info(users)")
            user_header = [row[1] for row in cursor.fetchall()]
            csv_writer.writerow(user_header)

            # Write the data rows for the 'users' table.
            csv_writer.writerows(user_rows)

        # Close the CSV file.
        csv_file.close()

        # Close the cursor and the database connection.
        cursor.close()
        connection.close()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

printDatabase()