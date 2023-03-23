import os
from flask import Flask, request, render_template
from nightfall import Confidence, DetectionRule, Detector, RedactionConfig, MaskConfig, Nightfall
from datetime import datetime, timedelta
import urllib.request, urllib.parse, json
import csv
import requests

app = Flask(__name__)

nightfall = Nightfall(
	key=os.getenv('NIGHTFALL_API_KEY'),
	signing_secret=os.getenv('NIGHTFALL_SIGNING_SECRET')
)
outfile = "results.csv"

# create CSV where sensitive findings will be written
headers = ["upload_id", "datetime", "org", "repo", "filepath", "before_context", "finding", "after_context", "detector", "confidence", "line_start", "line_end", "detection_rules", "commit_hash", "commit_date", "author_email", "permalink"]
with open(outfile, 'a') as csvfile:
	if os.stat(outfile).st_size == 0:
		writer = csv.writer(csvfile)
		writer.writerow(headers)

# respond to POST requests at /ingest
# Nightfall will send requests to this webhook endpoint with file scan results
@app.route("/ingest", methods=['POST'])
def ingest():
	data = request.get_json(silent=True)
	# validate webhook URL with challenge response
	challenge = data.get("challenge") 
	if challenge:
		return challenge, 200
	# challenge was passed, now validate the webhook payload
	else: 
		# get details of the inbound webhook request for validation
		request_signature = request.headers.get('X-Nightfall-Signature')
		request_timestamp = request.headers.get('X-Nightfall-Timestamp')
		request_data = request.get_data(as_text=True)

		if nightfall.validate_webhook(request_signature, request_timestamp, request_data):
			# check if any sensitive findings were found in the file, return if not
			if not data["findingsPresent"]: 
				print("No sensitive data present!")
				return "", 200

			# there are sensitive findings in the file
			output_results(data)
			return "", 200
		else:
			return "Invalid webhook", 500

# get hostname for API calls to GitHub cloud, GitHub enterprise, or GitLab
def get_hostname():
	if os.getenv('GIT_SERVICE') == 'gitlab': # gitlab
		return "gitlab.com/api/v4"

	if os.getenv('GIT_HOSTNAME') and os.getenv('GIT_HOSTNAME') != "github.com": # github enterprise
		return f"{os.getenv('GIT_HOSTNAME')}/api/v3"
	
	return "api.github.com" # github cloud

# get permalink to the line of the finding in the specific commit
def get_permalink(url, finding):
	path = finding['path'].split("/")
	if len(path) > 1:
		path.pop(0)
	path = "/".join(path)
	path = path.split(":")
	path = path[0]
	return path, f"{url}/blob/{finding['location']['commitHash']}/{path}#L{finding['location']['lineRange']['start']}"

# get details of the commit from git service
def get_commit(org, repo, commit_hash):
	if os.getenv('GIT_SERVICE') == 'gitlab': # gitlab
		headers = {
		    'Authorization': f"Bearer {os.getenv('GIT_PERSONAL_ACCESS_TOKEN')}"
		}
		url = f"https://{get_hostname()}/projects/{org}/repository/commits/{commit_hash}"
		response = requests.get(url, headers=headers)
		commit = json.loads(response.content)
		return { "email": commit['committer_email'], "date": commit['created_at'] }
	else: # github
		headers = {
		    'Authorization': f"token {os.getenv('GIT_PERSONAL_ACCESS_TOKEN')}",
		    'Accept': 'application/vnd.github.v3+json'
		}
		url = f"https://{get_hostname()}/repos/{org}/{repo}/commits/{commit_hash}"
		response = requests.get(url, headers=headers)
		commit = json.loads(response.content)
		return commit['commit']['author']

# send finding as JSON to an event collector HTTP endpoint
def send_to_event_collector(data):
	if os.getenv('EVENT_COLLECTOR_URL'): 
		resp = requests.post(os.getenv('EVENT_COLLECTOR_URL'), data=json.dumps(data))
		print(f"\tSent to event collector with status code {resp.status_code}")

# output findings to CSV
def output_results(data):
	findings_url = data['findingsURL']
	# open findings URL provided by Nightfall to access findings
	with urllib.request.urlopen(findings_url) as url:
		findings = json.loads(url.read().decode())
		findings = findings['findings']

	filepath, url, org, repo = "", "", "", ""
	if 'requestMetadata' in data:
		metadata = data['requestMetadata']
		metadata = json.loads(metadata)
		filepath = metadata['filepath']
		url = metadata['url']
		org = metadata['org_name']
		repo = metadata['repo_name']

	print(f"Sensitive data found in {filepath} | Outputting {len(findings)} finding(s) to CSV | UploadID {data['uploadID']}")
	table = []

	# loop through findings JSON, get relevant finding metadata, write each finding as a row into output CSV
	for i, finding in enumerate(findings):
		before_context = ""
		if 'beforeContext' in finding:
			before_context = repr(finding['beforeContext'])
		after_context = ""
		if 'afterContext' in finding:
			after_context = repr(finding['afterContext'])
		
		filepath, permalink = get_permalink(url, finding)
		commit_author = get_commit(org, repo, finding['location']['commitHash'])

		result = {
			"upload_id": data['uploadID'], 
			"datetime": str(datetime.now()),
			"org": org, 
			"repo": repo, 
			"filepath": filepath, 
			"before_context": before_context, 
			"finding": repr(finding['finding']), 
			"after_context": after_context, 
			"detector": finding['detector']['name'], 
			"confidence": finding['confidence'], 
			"line_start": finding['location']['lineRange']['start'], 
			"line_end": finding['location']['lineRange']['end'], 
			"detection_rules": finding['matchedDetectionRuleUUIDs'], 
			"commit_hash": finding['location']['commitHash'], 
			"commit_date": commit_author['date'], 
			"author_email": commit_author['email'], 
			"permalink": permalink
		}

		row = list(result.values())
		table.append(row)

		with open(outfile, 'a') as csvfile:
			writer = csv.writer(csvfile)
			writer.writerow(row)

		send_to_event_collector(result)
	return
