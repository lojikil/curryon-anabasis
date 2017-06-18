import os
import uuid
import re
from bottle import route, request, run, hook, redirect, app, view, template, response
from beaker.middleware import SessionMiddleware


key='5a17b238-13b5-4401-9d30-aab238a820eb'
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
template_cache = {}
stripusername = re.compile('[^a-zA-Z0-9]*')
badsurvey = re.compile('[^0-9\-a-z]')
xsscheck = re.compile('\<\s*(script|img|div|b|p|object|i|em|style)\s*>', re.I)


def checkreferer(ref):
    if ref.startswith("http://localhost:"):
        pass
    elif ref.startswith("http://127.0.0.1:"):
        pass
    elif ref.startswith("http://r.lojikil.com:"):
        pass
    elif ref.startswith("http://45.76.9.79:"):
        pass
    else:
        redirect("/hacker")


def checkantixss(data):
    if xsscheck.search(data) is not None:
        redirect("/hacker")

@hook('before_request')
def hostcheck():
    session = request.environ.get('beaker.session')
    path = request.urlparts.path
    ref = request.environ.get('HTTP_REFERER')
    origin = request.environ.get('HTTP_ORIGIN')
    response.set_header('X-XSS-Protection', '0')

    if path != '/login' and path != '/signup' and 'loggedin' not in session:
        redirect('/login')

    if ref is not None:
        checkreferer(ref)
    elif ref is None and request.method == "POST":
        redirect("/hacker")

    if origin is not None:
        checkreferer(origin)


@route('/login', method=['post', 'get'])
def login():
    if request.method == "POST":
        user = stripusername.sub("", request.POST.get("user", ''))
        pswd = request.POST.get("password", '')
        session = request.environ.get('beaker.session')
        if user == '' or pswd == '':
            return "Login failed"
        try:
            with file('./users/{0}.dat'.format(user)) as fh:
                data = fh.read().strip()
            if pswd != data:
                return "Login failed"
        except:
            return "Login failed"
        session['loggedin'] = True
        session['user'] = user
        return redirect('/')
    else:
        return template('login')


@route('/signup', method=['post', 'get'])
def signup():
    if request.method == "POST":
        user = stripusername.sub("", request.POST.get("user", ''))
        pswd = request.POST.get("password", '')
        cnfm = request.POST.get("confirmp", '')
        session = request.environ.get('beaker.session')
        if user == '' or pswd == '':
            return "Registration failed"
        elif pswd != cnfm:
            return "Password must match confirmation password"
        try:
            filename = './users/{0}.dat'.format(user)
            if os.path.isfile(filename):
                return "User exists"
            with open(filename, 'w') as fh:
                fh.write(pswd)
        except Exception as e:
            print e
            return "Registration failed exceptionally"
        session['loggedin'] = True
        session['user'] = user
        return redirect('/')
    else:
        return template('signup')


@route('/')
def index():
    return template('index')


@route('/hacker')
def hacker():
    return template('haqqr')


@route('/search', method=['post', 'get'])
def search():
    if request.method == "POST":
        q = request.POST.get("q", "")
        return template('search_results', q=q)
    else:
        return template('search')


@route('/survey', method=['post', 'get'])
def create_view():
    if request.method == "POST":
        survey = request.POST.get("survey_form", "")
        checkantixss(survey)
        survey_id = uuid.uuid4()
        with open('./forms/{0}.html'.format(survey_id), 'w') as fh:
            fh.write(survey)
        return template('survey_success', survey_id=survey_id)
    else:
        return template('survey_create')


@route('/survey/<surveyname>', method=['post', 'get'])
def view_survey(surveyname):

    if badsurvey.search(surveyname) is not None:
        redirect('/hacker')

    if os.path.isfile('./forms/{0}.html'.format(surveyname)):
        if request.method == "POST":
            form_data = request.body.read()
            form_id = uuid.uuid4()
            with open('./data/form-data/{0}-{1}.dat'.format(surveyname, form_id), 'w') as fh:
                fh.write(form_data)
        else:
            with open('./forms/{0}.html'.format(surveyname), 'r') as fh:
                form = fh.read()
            return template('view_survey', survey=form)
    else:
        return template('no_such_survey')


@route('/surveys')
@view('surveys')
def surveys():
    surveys = os.listdir('./forms')
    final = []
    for survey in surveys:
        if survey.endswith(".html"):
            final.append(survey.replace("./forms/", "").replace(".html",""))

    return template("surveys", surveys=final)


if __name__ == "__main__":
    session_opts = {
        'session.type': 'file',
        'session.cookie_expires': 300,
        'session.data_dir': './data',
        'session.auto': True
    }
    app = SessionMiddleware(app(), session_opts)
    run(host='0.0.0.0', port=8085, app=app)
