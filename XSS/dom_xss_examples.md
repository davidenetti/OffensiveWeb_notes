# Function that uses "document.write()" and concatenation of the input string

### Scenario:

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
```
With the document.write function it writes the "img" tag with the specified "src" parameter. In it there is a concatenation with the parameter that the user give to the page.

The parameter is taken from window.location.search and the parameter name is "search". If the is not empty then the JS function "trackSearch" is called.

N.B.: the window.location.search take anything which comes after the question mark in the URL.

In the DOM the passed element is displayed in the "img" tag created by the JS function:
```html
<img src="/resources/images/tracker.gif?searchTerms=test">
```

### Exploitation:

We can pass this string as input:

```
test" onload=alert()
```

Here, what happens is the following:
- The img tag is created as shown before;
- Now, due to the presence of " we are able to break the string automatically created by the JS function;
- The image is actually loaded, but given the presence of the onload action we inserted, the action specified in it will be perfomed after the image loading;
- We inserted the alert() function in the onload action, so we expect to see an alert box on the web page;
- We cannot close the " because there is that already inserted by the JS function.

The HTML resulting from this input is the following:
```html
<img src="/resources/images/tracker.gif?searchTerms=test" onload=alert()">
```