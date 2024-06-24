A typical web application works by receiving the HTML code from the back-end server and rendering it on the client-side internet browser. When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.

XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a medium risk (low impact + high probability = medium risk), which we should always attempt to reduce risk by detecting, remediating, and proactively preventing these types of vulnerabilities.


There are three main types of XSS vulnerabilities:
- **Stored (Persistent) XSS**: The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)
- **Reflected (Non-Persistent) XSS**:	Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)
- **DOM-based XSS**: Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)
