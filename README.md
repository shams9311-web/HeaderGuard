

\# HeaderGuard — Security Headers Checker



HeaderGuard is a beginner-friendly Python cybersecurity project that

checks HTTP response headers for commonly recommended web security headers.



\## Features



\- Accepts HTTP and HTTPS URLs

\- Checks six common security headers

\- Displays the HTTP status code and final URL

\- Follows HTTP redirects

\- Shows a header-presence summary and score

\- Saves scan results to `security\_report.txt`

\- Includes request timeouts and basic URL validation



\## Security Headers Checked



\- Content-Security-Policy

\- Strict-Transport-Security

\- X-Content-Type-Options

\- X-Frame-Options

\- Referrer-Policy

\- Permissions-Policy



\## Requirements



\- Python 3.10 or later

\- Internet connection

\- Python `requests` library



\## Installation



Clone the repository, then navigate into the project folder.



Install the dependency:



```bash

python -m pip install -r requirements.txt

```



\## Usage



Run the program:



```bash

python headguard.py

```



Enter a website URL when prompted, for example:



```text

https://example.com

```



The program displays the results and saves them to `security\_report.txt`.



\## Important Notes



\- The header-presence score is not an overall website security rating.

\- A present header may still be incorrectly configured.

\- Strict-Transport-Security is relevant only over HTTPS.

\- Only scan websites you own or have permission to assess.



\## Technologies



\- Python

\- Requests

\- HTTP security headers



