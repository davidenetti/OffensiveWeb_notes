**Mass Assignment** is a security flaw that occurs when an application automatically binds (assigns) a large set of user-provided input data (typically from a web form or API request parameters) directly to an object's attributes, such as a database model, without sufficiently filtering or validating which attributes are allowed to be modified.

## How the Attack Works

The core issue is the lack of a whitelist (a list of fields explicitly allowed for modification).

Normal Operation: A legitimate user sends a request to update their profile, including parameters for fields like name and email.

The Attack: An attacker intercepts this request and adds unauthorized, hidden parameters that correspond to sensitive internal attributes of the application's model, such as:
- role=admin
- is_premium=true
- user_id=123 (targeting another user's ID)

**Vulnerable Assignment**: The vulnerable application code takes the entire input set and "mass assigns" all values to the model object. The application unknowingly sets the attacker's role to admin or modifies another user's data, as it failed to distinguish between safe and sensitive parameters.

## Example
Let's assume that we have registered to a web application. After the registration process, we receive a message which says `Account is pending approval`. Let's also assume that we are assessing a web application and we have got the code of it.

```python
for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
  if k:
    session['user']=i
    return redirect("/home",code=302)
  else:
    return render_template('login.html',value='Account is pending for approval')
```

We can see that the application is checking if the value k is set. If yes, then it allows the user to log in. In the code below, we can also see that if we set the confirmed parameter during registration, then it inserts cond as True and allows us to bypass the registration checking step.

```python
try:
  if request.form['confirmed']:
    cond=True
except:
      cond=False
with sqlite3.connect("database.db") as con:
  cur = con.cursor()
  cur.execute('select * from users where username=?',(username,))
  if cur.fetchone():
    return render_template('index.html',value='User exists!!')
  else:
    cur.execute('insert into users values(?,?,?)',(username,password,cond))
    con.commit()
    return render_template('index.html',value='Success!!')
```

*In that case, what we should try is to register another user and try setting the confirmed parameter to a random value. Using Burp Suite, we can capture the HTTP POST request to the /register page and set the parameters `username=new&password=test&confirmed=test`*.

The mass assignment vulnerability is exploited successfully and we are now logged into the web app without waiting for the administrator to approve our registration request.