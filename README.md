# soc-analyst-Phising-Snapped-Phish-ing-Line

📝 Project Title:
TryHackMe – Snapped Phishing Line: Analyzing a Real-World Phishing Kit and Credential Harvesting Campaign

🎯 Objective:
Investigate a credential harvesting phishing campaign by tracing email artifacts, redirection URLs, and phishing kit archives. Analyze logs, domain records, and archive submissions to track adversary infrastructure, discover attacker email addresses, and extract IOCs from the deployed phishing kit.

🛠️ Tools Used:

VirusTotal
SSL Certificate Transparency Logs
Phishing Kit File Analysis
Open-source Intelligence (OSINT)
TryHackMe virtual environment
Hashing tools (SHA256)
Defanged URL analysis

❌ Skills Demonstrated:

Real-world phishing infrastructure investigation
Phishing kit reverse engineering
SSL certificate and archive submission timeline analysis
IOC (Indicator of Compromise) extraction
Email and credential collection path tracing
Project Overview
This investigation revolved around a phishing attack targeting a specific user with a PDF attachment. The adversary used redirection techniques and hosted a phishing kit archive to harvest credentials. The goal was to reconstruct the attack chain, from email delivery and redirection, to phishing page behavior, and finally to adversary infrastructure including credential collection endpoints.

Task Breakdown:

✏️ Task 1: Identify the Target
⭕️ Objective: Who is the individual who received an email attachment containing a PDF?

⭕️ Method: Inspect the provided email logs or metadata to locate the targeted recipient.

🔱 Answer: William McClean

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/1-1.png)  

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/1-2.png)   

✏️ Task 2: Sender Address
⭕️ Objective: What email address was used by the adversary to send the phishing emails?

⭕️ Method: Analyze the "From" or "Return-Path" in the phishing email headers.

🔱 Answer: Accounts.Payable@groupmarketingonline.icu

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/2-1.png)   

✏️ Task 3: Redirection URL for Zoe Duncan
⭕️ Objective: What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

⭕️ Method: Follow redirection chains from email or PDF link artifacts in a defanged format (e.g., hxxp://).

🔱 Answer: hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/3-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/3-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/3-3.png)  

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/3-4.png)   

✏️ Task 4: Phishing Kit Download Location
⭕️ Objective: What is the URL to the .zip archive of the phishing kit? (defanged format)

⭕️ Method: Inspect the infrastructure used to host the phishing kit and retrieve the archive URL.

🔱 Answer: hxxp[://]kennaroads[.]buzz/data/Update365[.]zip

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/4-1.png)   

✏️ Task 5: Phishing Kit Hash
⭕️ Objective: What is the SHA256 hash of the phishing kit archive?

⭕️ Method: Use VirusTotal or a local hashing tool to extract the SHA256 value.

🔱 Answer: ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/5-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/5-2.png)   

✏️ Task 6: Archive Submission Time
⭕️ Objective: When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

⭕️ Method: Check VirusTotal’s “First Submission” timestamp on the archive file.

🔱 Answer: 2020-04-08 21:55:50 UTC

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/6-1.png)  

✏️ Task 7: SSL Certificate Logging Time
⭕️ Objective: When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)

⭕️ Method: Query SSL certificate transparency logs using tools like crt.sh.

🔱 Answer: 2020-06-25 (Answer Provided By TryHackMe)

✏️ Task 8: Victim Who Submitted Password Twice
⭕️ Objective: What was the email address of the user who submitted their password twice?

⭕️ Method: Analyze the logs or phishing kit credentials dump for duplicate entries.

🔱 Answer: michael.ascot@swiftspend.finance

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/8-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/8-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/8-3.png)   

✏️ Task 9: Credential Collection Email
⭕️ Objective: What was the email address used by the adversary to collect compromised credentials?

⭕️ Method: Extract email address used as a collection endpoint in the phishing kit's backend code.

🔱 Answer: m3npat@yandex.com

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/9-1.png)   

✏️ Task 10: Additional Gmail Account
⭕️ Objective: The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

⭕️ Method: Analyze the phishing kit source files for additional email strings.

🔱 Answer: jamestanner2299@gmail.com

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/10-1.png)  

✏️ Task 11: Final Hidden Flag
⭕️ Objective: What is the hidden flag?

⭕️ Method: Search through phishing kit metadata, source code, or embedded comments for flag syntax.

🔱 Answer: THM{pL4y_w1Th_tH3_URL}

📸 Screenshot Space: 

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/11-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/11-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/11-3.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-Phising-Snapped-Phish-ing-Line/blob/d5921d5f6da4d4a61f44989040586aad3a15bd27/11-4.png) 

🔍 Analysis and Reflection

💡 Challenges Faced:

Following URL redirection paths through multiple layers
Extracting precise timestamps from VirusTotal and SSL certs
Parsing email addresses from phishing kit source code

💡 Lessons Learned:

Adversaries often reuse email addresses across phishing kits
Certificate transparency can aid in infrastructure detection
A single phishing archive can reveal the entire attack pipeline

💡 Relevance to SOC Analyst Roles:

Enhances skills in identifying and dissecting phishing kits
Reinforces understanding of phishing infrastructure timelines
Builds experience in analyzing stolen credential flows

💡 Relevance to Penetration Testing / Red Teaming:

Demonstrates how attackers structure phishing campaigns
Offers insight into evasion techniques and infrastructure reuse
Shows how simple ZIP kits can cause real-world breaches

✅ Conclusion

💡 Summary: This lab traced a phishing campaign from a deceptive email to credential collection using a ZIP-delivered phishing kit. By uncovering redirection links, SSL cert logs, and adversary-controlled email addresses, I extracted valuable IOCs and revealed attacker infrastructure. This room added real-world threat hunting depth beyond email headers — focusing on phishing infrastructure and archive analysis.

💡 Skills Gained:

URL redirection and phishing kit analysis
SSL certificate timeline investigation
Hashing and credential flow tracing
IOC extraction for threat intel use

💡 Next Steps:

Automate phishing kit analysis using custom scripts
Create Sigma rules to detect .zip archive delivery via email
Track certificate reuse across similar phishing domains
