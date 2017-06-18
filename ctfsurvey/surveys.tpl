<html>
  <head><title>CTFSurvey</title></head>
  <body>
    <h1>CTFSurvey::Current Surveys:</h1>
    % for item in surveys:
      <a href="/survey/{{item}}">{{item}}</a>
    % end
  </body>
</html>
