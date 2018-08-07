#################################################################################
#   Copyright © 2017 DCScoder
#
#                           ~ BMW Contacts Parser ~
#
#   Description:  Parses BMW contact entries from 'contactbook_YYYYMMDD.db' SQLite
#                 database file and extracts the data into an .html report.
#
#   Support:      Tested on contacts from NBT systems
#
#   Usage:        python  BMW_contacts_parser.py  <InputDir>
#
#################################################################################

import sqlite3
import logging
import hashlib
import re
import sys
import os

__version__ = 'v1.0'
__author__ = 'DCScoder'
__email__ = 'dcscoder@gmail.com'


# Input source file directory path
binary_file = os.path.join(sys.argv[1])

# Reads 16 byte file header to confirm file type is SQLite database
def check_file_signature(binary_file):
    file_header = b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00'
    f = open(binary_file, "rb")
    header_data = f.read(16)
    result = re.match(file_header, header_data)
    if result:
        return True
    else:
        return False

def main():
	# Create a log of processes
	# Logging = logging.info('Information') logging.warning('Warning') logging.error('Error')
	logging.basicConfig(filename='BMW_contacts_parser_log.txt', filemode='w',
		                format='%(asctime)s | %(lineno)s | %(levelname)s: %(message)s',level=logging.INFO)

	print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	print("~ BMW Contacts Parser " + __version__ + " developed by",__author__, "~")
	print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

	# Check source file is present in directory provided
	try:
		file_present = open(binary_file)
	except:
		logging.error("File not found, ensure source file is present!")
		logging.error("Attempted source file directory path: " + binary_file)
		sys.exit("ERROR - see log for more information!")

	# Checks file header to confirm file type is SQLite database
	sig_check_result = check_file_signature(binary_file)
	if sig_check_result == True:
		print("File signature check undertaken: match")
		logging.info("File signature check undertaken: match")
	else:
		logging.error("File signature check undertaken: no match | Unable to process as file is not a SQLite database!")
		sys.exit("ERROR - see log for more information!")

	print("Python script initialised...")
	logging.info("Python script initialised")

	# Read all bytes from file
	print("Reading file...")
	f = open(binary_file, "rb")
	all_data = f.read()
	total_bytes = len(all_data)
	print(total_bytes, "bytes read")
	logging.info("File read")
	logging.info(total_bytes)

	# Create MD5 and SHA1 hash values of source file
	print("Creating MD5 and SHA1 hashes of file...")
	my_hash_1 = hashlib.md5()
	my_hash_2 = hashlib.sha1()
	my_hash_1.update(all_data)
	my_hash_2.update(all_data)
	hash_string_1 = my_hash_1.hexdigest()
	hash_string_2 = my_hash_2.hexdigest()
	filehash = print("MD5 Hash:", hash_string_1)
	filehash = print("SHA1 Hash:", hash_string_2)
	logging.info("MD5 hash: " + hash_string_1)
	logging.info("SHA1 hash: " + hash_string_2)

	# Attempt to connect to database
	try:
		connection = sqlite3.connect(binary_file)
		c = connection.cursor()
	except sqlite3.DatabaseError:
		logging.error("Could not connect to SQLite database!")
		sys.exit("ERROR - see log for more information!")

	# Attempt to execute SQL queries and return all records requested
	try:
		print("Analysing SQL data...")
		contacts_data = c.execute("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, contact_card_phone.AdditionalName, "
								  "contact_card_phone.Url, contact_card_phone.organisation, "
								  "phone_data_phone.PhoneNumber, msg_data_phone.EmailAddr, "
								  "address_phone.StreetHousenumber, address_phone.City, address_phone.State,"
								  " address_phone.Country, address_phone.Postalcode FROM contact_card_phone "
								  "LEFT JOIN phone_data_phone ON contact_card_phone.Contact_ID = phone_data_phone.Contact_ID "
					              "LEFT JOIN msg_data_phone ON contact_card_phone.Contact_ID = msg_data_phone.Contact_ID "
								  "LEFT JOIN address_phone ON contact_card_phone.Contact_ID = address_phone.Contact_ID "
								  "ORDER BY contact_card_phone.GivenName").fetchall()

		logging.info("SQL queries executed")
	except sqlite3.DatabaseError:
		logging.error("Could not execute SQL queries!")
		sys.exit("ERROR - see log for more information!")
	c.close()

	# List notable column headings
	headings = ("Contact ID", "First Name", "Surname", "Other Name(s)", "URL", "Organisation", "Number(s)", "Email",
			   "Street/House no", "City", "State", "Country", "Post Code")

	print("Generating report...")

	# Create .html output file and format
	try:
		outputHTML = open("BMW_contacts_report.html", 'w', encoding='UTF-8')
	except:
		logging.error("Could not generate .html report!")
		sys.exit("ERROR - see log for more information!")

	# Create .html title
	outputHTML.write('<!DOCTYPE html><html><head><meta charset="UTF-8"><br><center><b>Contacts</b> \
	</center><style>body,td,tr {font-family: Arial; font-size: 14px;}</style></head><br><center><i> \
	Report created using BMW_contacts_parser.py</i><br><br>\n')

	# Create .html table headers
	outputHTML.write('<body><table border="1" cellpadding="2" cellspacing="0" align="center" bgcolor="#e3ecf3"> \
	<tr><th nowrap>Contact ID</th><th width="150">First Name</th><th width="150">Surname</th><th width="150">Other Name(s)</th> \
	<th>URL</th><th>Organisation</th><th>Number(s)</th><th>Email</th><th>Street/House no</th><th>City</th><th>State</th> \
	<th>Country</th><th>Post Code</th></tr>\n')

	# Single loop for all data formats
	for contact_entry in contacts_data:
		contact_entry = list(contact_entry)
		contact_entry[12] = (contact_entry[12])

		# Write .html
		outputHTML.write('<tr><td><center>{0}</center></td> \
		<td>{1}</td> \
		<td>{2}</td> \
		<td>{3}</td> \
		<td>{4}</td> \
		<td><center>{5}</center></td> \
		<td><center>{6}</center></td> \
		<td><center>{7}</center></td> \
		<td><center>{8}</center></td> \
		<td><center>{9}</center></td> \
		<td><center>{10}</center></td> \
		<td><center>{11}</center></td> \
		<td><center>{12}</center></td></tr> \n'.format(*contact_entry))

	outputHTML.write("</table></body></html>")

	outputHTML.close()
	print(".html report generated")
	logging.info(".html report generated")

	print("Python script terminated")
	logging.info("Python script terminated")

if __name__ == "__main__":
	main()