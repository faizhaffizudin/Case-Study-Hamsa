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
- Server Leaks Version Information via "Server" HTTP Response Header Field <br>
![image](https://user-images.githubusercontent.com/84786688/236850642-bd12f601-aa98-4056-b126-2c8a226764f0.png)
    - Server used is Apache v2.4.41 as shown by the response: <br>
    ![image](https://user-images.githubusercontent.com/84786688/236831136-61c029f5-ef54-4b0b-a19c-81a8f527637e.png)
    - CWE ID: 200 - Exposure of Sensitive Information to an Unauthorized Actor
    - Low risk
- Cross-Domain JavaScript Source File Inclusion <br>
    ![image](https://user-images.githubusercontent.com/84786688/236828248-fc2dcc10-2063-4118-950c-38ec486b740b.png)
    - Server-Side Scripting used is JavaScript as shown by the script source .js extension: <br>
    ![image](https://user-images.githubusercontent.com/84786688/236831810-e31b36c3-2f4e-42d3-9a9b-4453867709e1.png)
    - CWE ID: 829 - Inclusion of Functionality from Untrusted Control Sphere
    - Low risk
#### Evaluate:
- Server Leak: 
    - The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
    - Since it is revealed that server OS Apache v2.4.41 is used, attackers can exploit vulnerabilities targeting the OS version.  
- Cross-Domain:
    - The page includes one or more script files from a third-party domain.
    - Without sufficient protection mechanisms, the functionality could be malicious in nature (either by coming from an untrusted source, being spoofed, or being modified in transit from a trusted source). The functionality might also contain its own weaknesses, or grant access to additional functionality and state information that should be kept private to the base system, such as system state information, sensitive application data, or the DOM of a web application.
    - This might lead to many different consequences depending on the included functionality, but some examples include injection of malware, information exposure by granting excessive privileges or permissions to the untrusted functionality, DOM-based XSS vulnerabilities, stealing user's cookies, or open redirect to malware
#### Prevent:
- Server Leak:
    - Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.
    - Phase: Architecture and Design
        - Strategy: Separation of Privilege
        - Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.
        - Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.
- Cross-Domain:
    - Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.
    - Environment hardening (run your code using the lowest privileges that are required to accomplish the necessary tasks), surface reduction, input validation and enforcment by conversion can also be used.
    - Application firewall can also be used, that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth.

Observed examples can be seen on cwe links in the references below. <br>
Reference: https://cwe.mitre.org/data/definitions/200.html <br>
https://cwe.mitre.org/data/definitions/829.html
### <a name="hash"/> b. Hash Disclosure
#### Identify:
- No alerts, i.e. no vulnerability detected by the automated scan. There is also no risk level and cwe assigned on ZAP's alert page (https://www.zaproxy.org/docs/alerts/10097/). 
#### Evaluate:
- N/a for this website. The definition of it is a hash that was disclosed/leaked by the web server.
#### Prevent:
- N/a for this website. Otherwise, ensure that hashes that are used to protect credentials or other resources are not leaked by the web server or database. There is typically no requirement for password hashes to be accessible to the web browser.
### <a name="csrf"/>c. CSRF
#### Identify:
- Absence of Anti-CSRF Tokens <br>
![image](https://user-images.githubusercontent.com/84786688/236832647-6b3cc83f-7bf3-47d3-bfaf-437ccf56a98e.png) 
    - Eg. of absence: <br>
    ![image](https://user-images.githubusercontent.com/84786688/236835087-a25e23bf-86cd-4821-afb4-c0a5146725b0.png)
    - CWE ID: 352 - Cross-Site Request Forgery (CSRF)
    - Medium level risk
#### Evaluate:
Upon examination of HTML submission forms present on the website, it was discovered that no Anti-CSRF tokens were present. 

Anti CSRF tokens are (pseudo) random parameters used to protect against Cross Site Request Forgery (CSRF) attacks.
However they also make a penetration testers job harder, especially if the tokens are regenerated every time a form is requested.

Cross-site request forgery (CSRF) is an attack in which a victim unknowingly sends an HTTP request to a target destination to perform an action as the victim. The cause of this attack lies in application functionality using predictable URL/form actions in a repeatable manner. The trust that a website has for a user is exploited in CSRF attacks. While similar to cross-site scripting (XSS), which exploits the trust that a user has for a website, CSRF attacks are not necessarily cross-site but can be. Other names for CSRF attacks include XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in various situations, such as when the victim has an active session or is authenticated via HTTP auth on the target site. Additionally, CSRF can be used to disclose information by accessing the response, especially when the target site is vulnerable to XSS. This is because XSS can function as a platform for CSRF, enabling the attack to operate within the same-origin policy.

Observed examples:
- CVE-2004-1703 Add user accounts via a URL in an img tag
- CVE-2004-1995 Add user accounts via a URL in an img tag
- CVE-2004-1967 Arbitrary code execution by specifying the code in a crafted img tag or URL
- CVE-2004-1842 Gain administrative privileges via a URL in an img tag
- CVE-2005-1947 Delete a victim's information via a URL or an img tag
- CVE-2005-2059 Change another user's settings via a URL or an img tag
- CVE-2005-1674 Perform actions as administrator via a URL or an img tag
- CVE-2009-3520 modify password for the administrator
- CVE-2009-3022 CMS allows modification of configuration via CSRF attack against the administrator
- CVE-2009-3759 web interface allows password changes or stopping a virtual machine via CSRF

Reference: http://cwe.mitre.org/data/definitions/352.html

#### Prevent:
- Phase: Architecture and Design
    - During the Architecture and Design phase, it is recommended to use a reliable library or framework that prevents this weakness from occurring or provides tools that make it easier to avoid. One example is using anti-CSRF packages like OWASP CSRFGuard.
    - Generating a unique nonce for each form is also an effective strategy to avoid CSRF. It's essential to ensure that the nonce is not predictable to prevent attackers from bypassing this defense. However, this method can be bypassed using XSS.
    - Identifying and labeling dangerous operations is recommended. When a user performs a potentially harmful action, sending a separate confirmation request to ensure that the user intended to perform that operation can prevent CSRF attacks. However, this method can also be bypassed using XSS.

- ESAPI Session Management control can be utilized to prevent CSRF attacks as it includes a component specifically designed for this purpose.
- It's crucial to avoid using the GET method for any request that may trigger a state change to minimize the chances of CSRF attacks.

- Implementation Phases:
    - When implementing the application, it's essential to ensure that it's free of cross-site scripting issues, as most CSRF defenses can be bypassed using attacker-controlled scripts.
    - Checking the HTTP Referer header can help to identify if the request came from an expected page. However, it's important to note that this method can break legitimate functionality as users or proxies may have disabled sending the Referer header for privacy reasons.

Reference: http://projects.webappsec.org/Cross-Site-Request-Forgery

### <a name="sec"/> d. Secured Cookies
#### Identify:
- Identified as Cookie Without Secure Flag
- The risk is low
- CWE ID 614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- WASC ID 13
- A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections through Set-Cookie: cead32cbdaf3cab9ed422ebced5449f0
#### Evaluate:
- CVE-2004-0462: A product does not set the Secure attribute for sensitive cookies in HTTPS sessions, which could cause the user agent to send those cookies in plaintext over an HTTP session with the product. CVSS Score is 2.1
- CVE-2008-3663: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0
- CVE-2008-3662: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0
- CVE-2008-0128: A product does not set the secure flag for a cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0
- Related with CAPEC-102 (Session Sidejacking) which takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.
#### Prevent:
- Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.
- Always set the secure attribute when the cookie should sent via HTTPS only.

### <a name="csp"/>e. CSP
#### Identify:
- Risk level: medium
- Confidence: high
- CWE ID: 693
- The page involved is at URL: https://www.mohe.gov.my/*.css
#### Evaluate:
Content Security Policy(CSP) offers a layer of security that aids in detecting and mitigating specific sorts of threats, such as Cross-Site Scripting (XSS) and data injection attacks. Hackers use XSS attacks to deceive trustworthy websites into sending harmful material. The browser runs all code from trustworthy origins and cannot distinguish between legitimate and malicious code. Thus any inserted code is also executed.

CWE-693 denotes protection mechanism failure, which implies that this web application does not utilize or wrongly uses a protection mechanism that offers adequate defense against directed attacks. This weakness applies to three different circumstances. A "missing" protection mechanism happens when the application fails to declare any defense mechanism against a particular type of attack. An "insufficient" protection mechanism may provide certain defenses, such as against the most prevalent attacks, but it does not guard against all that is desired. Finally, an "ignored" mechanism happens when a mechanism is present and in active usage inside the product but has not been applied in some code path by the developer.
#### Prevent:
- Configure the webserver to return the Content-Security-Policy HTTP Header with values controlling which resources the browser can load for the page
- Writing JavaScript and CSS with CSP in mind
    - Because it constantly executes in the current context, inline code is a major injection vector that cannot be restricted. When CSP is enabled, it, by default, blocks all inline code. This implies no inline styles or scripts, including inline event handlers or javascript: URLs. Thus any new code should adhere to best practices and only utilize external script and style files.
- Page-level CSP directives
    - Use the sandbox directive to treat the page as if inside a sandboxed iframe. To increase security on older websites with many legacy HTTP pages, use the upgrade-unsafe-requests directive to rewrite insecure URLs. This directs user agents to transition HTTP to HTTPS in URL schemes and is useful when still having various HTTP URLs.

Reference: 
- https://www.invicti.com/blog/web-security/content-security-policy/
- https://cwe.mitre.org/data/definitions/693.html
- https://www.zaproxy.org/docs/alerts/10038-1/

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
- No alert found by OWASP ZAP. Thus, no risk level and CWE ID.
#### Evaluate:
- Not available on this website. But, from https://www.zaproxy.org/docs/alerts/10029/, this check examines user input in query string parameters and POST data to see where cookie parameters may be altered. This is known as a cookie poisoning attack, and it may be exploited when an attacker can change the cookie in various ways. While this may not be exploitable in some instances, enabling URL parameters to set cookie values is usually seen as a problem.
#### Prevent:
- Not available on this website. If not, the solution for this alert is not to enable the user to modify cookie names and values. If query string parameters must be placed in cookie values, ensure that semicolons are not used as name/value pair delimiters.

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
- Risk level: informational
- CWE ID: 200
- The page involved is at URL: https://www.mohe.gov.my/administrator/
- Evidence: administrator
![image](https://user-images.githubusercontent.com/121481219/236844193-4ee043a7-ea94-4b8f-91a8-6e2eb5b0ae67.png)
 
#### Evaluate:
Information disclosure is a vulnerability that can jeopardize the security of sensitive data in a web application. The vulnerability found in this situation is known as "Information Disclosure - Suspicious Comments." It refers to source code comments that might reveal sensitive information to an attacker. These suspicious comments may assist an attacker in obtaining information in some circumstances. The attacker can get further information about the web application by studying source code fragments and comments.

CWE-200, according to CWE by the Mitre Organisation, is one of the most significant downward movers in 2022, falling from #20 in 2021 to #33. The total number of National Vulnerability Database(NVD)s is 241, and the average CVSS score is 5.99. As a result, CWE-200 has a medium severity rating, indicating that the web application may be vulnerable to a possible attack.
![examples](https://user-images.githubusercontent.com/121481219/236845313-6e1f9831-4335-4d4f-bca8-e8314446b91c.jpg)
#### Prevent:
- Identify the suspicious comments
    -The first step in resolving this issue is to locate the suspicious code comments. These comments might contain sensitive information, debugging information, or        other facts that an attacker could use to uncover weaknesses in the web application.

- Remove the suspicious comments
    -Once the suspicious comments are identified, the following step is to delete them from the source code. Sensitive information should never be kept in comments          since anybody with access to the source code may readily access it. Just make sure that any sensitive information is removed before committing the code.

- Implement proper authentication and authorization 
    -Proper authentication and authorization must be implemented to secure the web application. This will ensure that critical information and functionality are only        accessible to authorized individuals.

Reference:
- https://cwe.mitre.org/data/definitions/200.html
- https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html
- https://www.zaproxy.org/docs/alerts/10027/
