<html>
  <head><title>login to CTFSurvey</title></head>
  <body>
    <h1>CTFSurvey login</h1>
    <form action="/login" method="POST">
        <label for="user">Username:</label>
        <input name="user" type="text">
        <br>
        <label for="password">Password:</label>
        <input name="password" type="password">
        <br>
        <input type="submit" value="Login">
    </form>
    <a href="/signup">Don't have an account? Create One!</a>
  </body>
</html>
