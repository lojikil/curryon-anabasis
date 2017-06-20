<html>
  <head><title>CTFSurvey</title></head>
  <body>
    <h1>CTFSurvey::Create Survey</h1>

    <p>Enter your Survey form code below. The only valid tags are <code>form</code>, 
    <code>label</code>, and <code>input</code>.</p>
    <form action="/survey" method="post">
    <textarea name="survey_form" rows="16" cols="128"></textarea>
    <br>
    <input type="submit" value="Create Survey">
    </form>
  </body>
</html>
