# Case Study

## Group Name
Hamsa

## Group Members
1. Mohd Faiz Hafizuddin bin Ahmad Yazi (2011837)
2. Muhammad Zaidi bin Abdul Razak (1820833)
3. Hani Arinah binti Hairul Azam (2019774)
4. Hani Nursyamira binti Muhamat Halis (2016478)

## Assigned Tasks
1. Mohd Faiz Hafizuddin bin Ahmad Yazi (2011837)
    - Identify, evaluate and prevent of:
      - Secured Cookies
      - CSP
      - JS Library.

2. Muhammad Zaidi bin Abdul Razak (1820833)
    - Identify, evaluate and prevent of:
      - Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.
      - Hash Disclosure.
      - CSRF.

3. Hani Arinah binti Hairul Azam (2019774)
    - Identify, evaluate and prevent of:
      - Cookie Poisoning.
      - Information Disclosure.

4. Hani Nursyamira binti Muhamat Halis (2016478)
    - Identify, evaluate and prevent of:
      - HTTPS implementation (TLS/SSL).
      - Potential XSS.

## Table of Contents
1. [Description](#desc)
2. [Observation Results](#obsv)
    1. [Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)](#serv)
    2. [Hash Disclosure](#hash)
    3. [CSRF](#csrf)
    4. [Secured Cookies](#sec)
    5. [CSP](#csp)
    6. [JS Library](#jsl)
    7. [HTTPS implementation (TLS/SSL)](#https)
    8. [Cookie Poisoning](#coo)
    9. [Potential XSS](#pot)
    10. [Information Disclosure](#inf)

## <a name="desc"/> Description
## <a name="obsv"/>Observation Results
### <a name="serv"/>a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)
#### Identify:
- No alerts but the Server OS can be identified from the response below: 
![image](https://user-images.githubusercontent.com/84786688/236816942-b77650b0-c9ba-4d94-bd66-0e5d024d2a2e.png)
- and also no alerts for Server Side-Scripting used but
#### Evaluate:
#### Prevent:
### <a name="hash"/> b. Hash Disclosure
#### Identify:
- No alerts.
#### Evaluate:
#### Prevent:
### <a name="csrf"/>c. CSRF
#### Identify:
- Absence of Anti-CSRF Tokens 
- Medium level risk
- CWE ID: 352
#### Evaluate:
#### Prevent:
### <a name="sec"/> d. Secured Cookies
#### Identify:
#### Evaluate:
#### Prevent:
### <a name="csp"/>e. CSP
#### Identify:
#### Evaluate:
#### Prevent:
### <a name="jsl"/>f. JS Library
#### Identify:
#### Evaluate:
#### Prevent:
### <a name="https"/>g. HTTPS Implementation (TLS/SSL)
#### Identify:
#### Evaluate:
#### Prevent:
### <a name="coo"/>h. Cookie Poisoning
#### Identify:
#### Evaluate:
#### Prevent:
### <a name="pot"/>i. Potential XSS
#### Identify:
  - Identified as User Controllable HTML Element Attribute.
  - The risk level is low.
  - Classified as CWE ID:20
  - The page involved is at URL: https://www.mohe.gov.my/korporat/profil-korporat 
#### Evaluate:
  - Passive
  - This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. 
  - This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.
  - User-controlled HTML attribute values were found. 
  - The user-controlled value was 10. 
#### Prevent:
  - Try injecting special characters to see if XSS might be possible.
  - Validate all input and sanitize output it before writing to any HTML attributes.
### <a name="inf"/>j. Information Disclosure
#### Identify:
#### Evaluate:
#### Prevent:
