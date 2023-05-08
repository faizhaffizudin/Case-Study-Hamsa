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
2. [Identify the vulnerabilities](#iden)
3. [Evaluate the vulnerabilities](#eval)
4. [Prevent the vulnerabilities](#prev)

## <a name="desc"/> Description

## <a name="iden"/> Identify the vulnerabilities
### a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)

### b. Hash Disclosure

### c. CSRF

### d. Secured Cookies

### e. CSP

### f. JS Library

### g. HTTPS Implementation (TLS/SSL)

### h. Cookie Poisoning

### i. Potential XSS
  - Identified as User Controllable HTML Element Attribute.
  - The risk level is low.
  - Classified as CWE ID:20
  - The page involved is at URL: https://www.mohe.gov.my/korporat/profil-korporat

### j. Information Disclosure
  
## <a name="eval"/> Evaluate the vulnerabilities
### a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)

### b. Hash Disclosure

### c. CSRF

### d. Secured Cookies

### e. CSP

### f. JS Library

### g. HTTPS Implementation (TLS/SSL)

### h. Cookie Poisoning

### i. Potential XSS
  - Passive
  - This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. 
  - This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.
  - User-controlled HTML attribute values were found. 
  - The user-controlled value was 10.

### j. Information Disclosure
 
## <a name="prev"/> Prevent the vulnerabilities
### a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)

### b. Hash Disclosure

### c. CSRF

### d. Secured Cookies

### e. CSP

### f. JS Library

### g. HTTPS Implementation (TLS/SSL)

### h. Cookie Poisoning

### i. Potential XSS
  - Try injecting special characters to see if XSS might be possible.
  - Validate all input and sanitize output it before writing to any HTML attributes.

### j. Information Disclosure
