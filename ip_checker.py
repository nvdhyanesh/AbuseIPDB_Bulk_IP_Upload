import csv
import requests


def check_ip_abuse(api_key, input_file, output_file):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # Write header row
        writer.writerow(['ipAddress', 'isPublic', 'ipVersion', 'isWhitelisted', 'abuseConfidenceScore',
                         'country', 'city', 'usageType', 'isp', 'domain', 'hostnames', 'totalReports',
                         'numDistinctUsers', 'lastReportedAt'])

        next(reader)  # Skip header row in input file
        for row in reader:
            ip = row[0]  # Assuming IP is in the first column
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }

            try:
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()['data']

                # Check if usage type matches the desired value
                if data.get('usageType') == "Data Center/Web Hosting/Transit":
                    writer.writerow([
                        data['ipAddress'],
                        data.get('isPublic', ''),
                        data.get('ipVersion', ''),
                        data.get('isWhitelisted', ''),
                        data.get('abuseConfidenceScore', ''),
                        data.get('countryName', ''),
                        data.get('city', 'N/A'), # city info is not provided by the API response
                        data.get('usageType', ''),
                        data.get('isp', ''),
                        data.get('domain', ''),
                        ','.join(data.get('hostnames', [])),
                        data.get('totalReports', ''),
                        data.get('numDistinctUsers', ''),
                        data.get('lastReportedAt', '')
                    ])
            except requests.exceptions.RequestException as e:
                print(f"Error checking IP {ip}: {e}")




if __name__ == "__main__":
    API_KEY = 'api_key'
    INPUT_FILE = 'path of input file' # use / in path so that python does not consider the path as literal
    OUTPUT_FILE = 'path of the output file' # use / in path so that python does not consider the path as literal

    check_ip_abuse(API_KEY, INPUT_FILE, OUTPUT_FILE)
    print("IP check completed. Results saved to", OUTPUT_FILE)
