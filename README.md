# CAS22_CS04
CODE MONKEYS- SOMNATH

              WEB APPLICATION VULNERABILITY SCANNER 

_Overview:

This project is  a lightweight vulnerability scanner tool. The primary goal is to flag common web application vulnerabilities, including SQL injection, Cross-Site scriptin(XSS), etc.

_Objectives:

•Identify Vulernabilities: Flag potential weak spots in web applications for common vulnerabilities.
•Modular Design: Utilize a class-based approach with dedicated functions for each vulnerability check.
•Rapid Feedback: Provide immediate console output of potential vulnerabilities without automated payload injections, ensuring a safe scanning process.

_Feature:

•SQL Injection Check: Analyzes URL parameters and form inputs to identify areas susceptible to SQL injection.
•XSS Detection: Scans web content to flag potential Cross-Site Scripting vulnerabilities.
•Open Redirect Identification: Detects URL manipulation issues that could lead to open redirect vulnerabilities.
•Scalability: Designed to easily incorporate additional vulnerability checks in the future.

_Technologies and Libraries
This tool is built using Python and leverages the following libraries:

•requests: 
           -Facilitates reliable HTTP request handling, session management and error checking. 
           -Ensure robust communication with target web applications.

•BeautifulSoup:
               -Provides powerful HTML parsing capabilities, enabling the extraction and analysis of web page content.
               -Suports the detection of embedded scripts and potential vulnerability indicators.

•urljoin & urlparse:
                    -Offers dependable methods for constructing and deconstructing urls.
                    -Simplify the handling of both relative and absolute url paths, ensuring accurate navigation and validation.

_Implementation Details:

•Class-Based Structure: The main scanner is encapsulated within a Python class, promoting code modularity and ease of maintenance.
•Separate Functions: Each vulnerability check is implemented as a separate function, allowing individual testing and future expansion.
•Console Output: Vulnerabilities are flagged and displayed directly in the console to provide immediate feedback during scans.

_Future Enhancement:

•Additional Vulnerability Checks:
Integrate further modules to detect vulnerabilities such as CSRF, Remote Code Execution, etc.

•Enhanced Reporting:
Develop a feature to generate detailed scan reports that summarize findings and provide risk assessments.

•User Interface Improvements:
Explore the creation of a lightweight GUI to enhance usability and provide interactive scanning capabilities.
