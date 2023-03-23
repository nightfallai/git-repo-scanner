# Git Sensitive Data Scanner

#### Scan the full commit history of all your git repositories in GitHub or GitLab for sensitive data (like PII and API keys) with Nightfall's data loss prevention (DLP) APIs.

This service uses Nightfall's [data loss prevention (DLP) APIs](https://nightfall.ai/developer-platform) to scan all git repos across your GitHub or GitLab account.

###### How it works
The service will (1) retrieve all git repos that your account is a member of, (2) send each git repo to Nightfall to be scanned, (3) scan the full commit history of each repo with Nightfall, (4) run a local webhook server that retrieves sensitive results back from Nightfall, and (5) write the sensitive findings to a CSV file. This output provides a comprehensive report/audit of the sensitive data at-rest in your GitHub or GitLab account. 

If you'd like a more detailed tutorial or walk-through of how this service works, we recommend reviewing our [file scanner tutorial](https://github.com/nightfallai/file-scanner-tutorial), as the components are largely the same.

###### Compatibility
The service is compatible with GitHub and GitLab instances that can be accessed over the Internet with the REST API and personal access tokens, meaning GitHub Cloud, GitHub Enterprise Server, GitLab SaaS, and GitHub Self-Managed. This service has only been tested on GitHub Cloud, an Internet-accessible GitHub Enterprise Server v3.3.1 instance, and a GitLab SaaS instance. For other versions or custom deployments, additional modifications may be required.

## Prerequisites

* Nightfall account - [sign up](https://app.nightfall.ai/sign-up) for free if you don't have an account
* GitHub or GitLab account - you'll need admin access to the orgs/repos you wish to scan and the ability to create a personal access token

## Usage

1. Install dependencies. Add the `-U` flag to ensure you're using the latest versions of these packages.

```bash
pip install -r requirements.txt
```

2. Create a local ngrok tunnel to point to your webhook server. Download and install ngrok via their quickstart documentation [here](https://ngrok.com/docs/getting-started/).

```bash
./ngrok http 8000
```

3. Create a [Detection Rule](https://docs.nightfall.ai/docs/creating-detection-rules) in the Nightfall console. This will define what sensitive data you are looking for. You'll need your detection rule UUID for an upcoming step. You can create and use multiple detection rule UUIDs if you'd like.

4. Get GitHub/GitLab details. You'll need your username, Personal Access Token, and hostname for the next step.

	###### 4.a. If GitHub:

* Create a [Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token). For assigning permissions to the token, check the box for the `repo` category permission. Ensure that your GitHub account has sufficient permissions/access, as that will dictate what this token can access. 

* If you use GitHub.com, your hostname is `github.com`. If you use GitHub Enterprise, your hostname is the subdomain of your Enterprise installation, e.g. `code.acme-corp.com`.

	###### 4.b. If GitLab:

* Create a [Personal Access Token](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html). For assigning permissions to the token, check the box for the `read_api` category.

* If you use GitLab SaaS, your hostname is simply `gitlab.com`. If you use GitLab Self-Managed, your hostname is the subdomain of your Self-Managed installation, e.g. `code.acme-corp.com`.

5. Set your environment variables: your Nightfall API key, your Nightfall signing secret, your Nightfall [detection rule UUIDs](https://docs.nightfall.ai/docs/creating-detection-rules) (from earlier step), your webhook server URL from ngrok, and your GitHub or GitLab details (from earlier step).

```bash
export NIGHTFALL_API_KEY=<your key here>
export NIGHTFALL_SIGNING_SECRET=<your secret here>
export NIGHTFALL_DETECTION_RULE_UUIDS=<comma separated list of your detection rule uuids>
export NIGHTFALL_SERVER_URL=https://<your server subdomain>.ngrok.io
```

###### 5.a. If GitHub, add:

```bash
export GIT_SERVICE=github
export GIT_USERNAME=<your username>
export GIT_PERSONAL_ACCESS_TOKEN=<your github personal access token>
export GIT_HOSTNAME=<your github hostname>

# Optionally, you can exclude a list of orgs whose contents you don't want to scan.
export GIT_EXCLUDE_ORGS=<one org>,<another org>
```

###### 5.b. If GitLab, add:

```bash
export GIT_SERVICE=gitlab
export GIT_USERNAME=<your username>
export GIT_PERSONAL_ACCESS_TOKEN=<your github personal access token>
export GIT_HOSTNAME=<your github hostname>
```

###### 5.c. If sending findings to an event collector, add:

Optional. If you'd like to send each sensitive finding as JSON to an HTTP event collector, such as an endpoint configured in your SIEM like Sumo Logic or Splunk, set the `EVENT_COLLECTOR_URL` environment variable. If this variable is not set, findings will not be sent to an event collector. For example:

```bash
export EVENT_COLLECTOR_URL=https://endpoint1.collection.us1.sumologic.com/receiver/v1/http/...
```

6. Start your webhook server. This runs `app.py`.

```bash
gunicorn app:app
```

7. In a new process/window, run your scan. Ensure your environment variables are set in this new window as well.

```python
python scanner.py
```

8. Monitor your webhook server output. Once all file scan events have been received and the scan is complete, view your results in `results.csv`. Each row in the output CSV will correspond to a sensitive finding. Each row will have the following fields, which you can customize in your webhook server in `app.py`: 

* `upload_id` - Upload ID provided by Nightfall
* `datetime` - Timestamp of when the finding was generated
* `org` - Organization/owner name if GitHub; Project ID if GitLab
* `repo` - git repo name
* `filepath` - Filepath
* `before_context` - Characters before the sensitive finding (for context)
* `finding` - Sensitive finding itself
* `after_context` - Characters after the sensitive finding (for context)
* `detector` - Detector that was found, see Detector Glossary
* `confidence` - Confidence level of the detection
* `line_start` - Line number of where the finding starts in the file
* `line_end` - Line number of where the finding ends in the file
* `detection_rules` - Corresponding detection rules that flagged the sensitive finding
* `commit_date` - Timestamp of commit
* `author_email` - Email of author of commit
* `permalink` - Link to the line of the commit

## Troubleshooting

###### Scenario:
```
stderr: 'fatal: destination path 'repos-temp/xyz' already exists and is not an empty directory.
```

###### Solution:

The service works by downloading a temporary local copy of your git repos in a directory called `repos-temp` in the same directory in which the script is executed. These temporary files are cleaned up at the end of successful execution. If the scan errors midway through execution, these temporary files may not be removed completely. In which case, you can use the `delete_all_repos()` function in `app.py` or simply delete the `repos-temp` directory and retry.

---

###### Scenario:

```API rate limit exceeded for xxx.xxx.xxx.xxx.```

###### Solution:

This service does not currently take GitHub rate limits into account.

---

###### Scenario:

Results file has old findings from earlier runs.

###### Solution:

This service appends to `results.csv`. If you no longer want the contents of `results.csv`, delete the file and restart your server. This will recreate the file from scratch.

## License

This code is licensed under the terms of the MIT License. See [here](LICENSE.md) for more information.