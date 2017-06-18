import web
from bottle import run, app
from paste.translogger import TransLogger
import logging
import time
from beaker.middleware import SessionMiddleware

start_stamp = time.ctime().replace(' ', '-')

logging.basicConfig(filename="logs/paste-{0}.log".format(start_stamp),
                    filemode="w",
                    level=logging.INFO)
wsgil = logging.getLogger('wsgi')
ch = logging.FileHandler("logs/wsgi-{0}.log".format(start_stamp))
wsgil.addHandler(ch)
app = TransLogger(app())
session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './data',
    'session.auto': True
}
app = SessionMiddleware(app(), session_opts)

run(port=8080,
    host='0.0.0.0',
    server='paste',
    app=app)
