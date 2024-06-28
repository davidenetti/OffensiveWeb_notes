# Stored XSS into anchor "href" attribute with double quotes HTML encoded

### Scenario
We have a blog post regular page (a list of blog post). Inside these, we have a section to comment the post. These comment, probably, are stored in a DB and loaded when the specified blog post page is loaded.
One the field we can insert during a comment is a website.

If we inspect the page we can see the folowing:
```html
<a id="author" href="www.example.com">test</a>
```
So, in other words, our inserted website will populate an "href" attribute inside an anchor tag.

We can notice that we can specify also a javascript code. In particular, we can directly execute JS inside an href attribute by using ```javascript:```.

### Exploit

We will use something like this:
```
javascript:alert()
```
