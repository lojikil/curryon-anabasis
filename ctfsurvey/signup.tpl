<html>
  <head><title>signup for CTFSurvey</title></head>
  <body>
    <h1>CTFSurvey signup</h1>
    <form action="/signup" method="POST">
        <label for="user">Username:</label>
        <input name="user" type="text">
        <br>
        <label for="password">Password:</label>
        <input name="password" type="password">
        <br>
        <label for="confirmp">Confirm Password:</label>
        <input name="confirmp" type="password">
        <br>
        <input type="submit" value="Signup">
    </form>
    <a href="/login">Have an account? Log in!</a>
  </body>
</html>
