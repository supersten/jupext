from curses import raw
import uuid

from traitlets import Bool
from tornado import gen

from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
import base64
import hmac
import hashlib
import json

class stensAuthHandler(BaseHandler):

    @gen.coroutine
    def get(self):
        inkspot_user = self.get_argument('code', None, True)
        raw_user = yield self.get_current_user()
        print('printing raw user')
        print(raw_user)
        if(raw_user is not None and raw_user.escaped_name != "supersten"):
            print('you cant come here')
            self.clear_login_cookie()
            html = yield self.render_template('error.html',status_code = 'Error', status_message = 'You should log in through Salesforce')
            self.finish(html)     
        if(inkspot_user == 'supersecret' and raw_user == None):
            self.clear_login_cookie()
            raw_user = self.user_from_username("supersten")
            self.set_login_cookie(raw_user)
            self.redirect(self.get_next_url(raw_user))
        if(inkspot_user == 'supersecret' and raw_user.escaped_name == "supersten"):
            self.redirect(self.get_next_url(raw_user))
        else:
            print('you cant come here')
            self.clear_login_cookie()
            html = yield self.render_template('error.html',status_code = 'Error', status_message = 'You should log in through Salesforce')
            self.finish(html)          
        '''if(raw_user):
            user = yield self.login_user(raw_user)
            next_url = self.get_next_url(user)
            print(next_url)
            self.redirect(next_url)
        else:
            raise self.web.HTTPError(403)
        if inkspot_user == "":
            raise web.HTTPError(401)
        if inkspot_study == "":
            raise web.HTTPError(401)

        userDict = {
        'name': 'inkspot_user3333',
        'studyFolder': 'inkspot_study'
    }
        self.log.warning(
            "sTUPID")
        print('equally stupdi')

        user = yield self.login_user(userDict)

        #self.set_login_cookie(raw_user)
        #user = yield gen.maybe_future(self.process_user(raw_user, self))
        #self.redirect(self.get_next_url(raw_user))
        #user = yield self.login_user(userDict)
        next_url = self.get_next_url(user)
        print(next_url)
        self.redirect(next_url)'''

    @gen.coroutine    
    def post(self):
        #self.clear_login_cookie()
        print('here is is')
        raw_user = yield self.get_current_user()
        userDict = {
        'name': 'inkspot_user314445',
        'refreshToken': 'inkspot_study'
        }   
        user = yield self.login_user(userDict)
        raw_user2 = yield self.get_current_user()
        self.set_login_cookie(user)
        print(self.get_next_url(user))
        #user2 = yield gen.maybe_future(self.process_user(user, self))
        body_argument = self.get_body_argument(
            name='custom_next',
            default=self.get_next_url(user),
        )

        #self.redirect(body_argument) 
        self.redirect(self.get_next_url(user))



class stensAuthHandler2(BaseHandler):

    @gen.coroutine
    def get(self):
        print('this worked!!')
        userDict = {
        'name': 'inkspot_user_login2',
        'studyFolder': 'inkspot_study'
        }
        #user = yield self.login_user(userDict)
        user = yield self.get_current_user()
        next_url = self.get_next_url(user)
        self.redirect(next_url)
    
    @gen.coroutine
    def post(self):
        tkn = self.get_token(self.get_body_argument('signed_request'))
        if(tkn):
            userDict = {
            'name': tkn['user'],
            'refreshToken': tkn['tkn']
            }
        else:            
            html = yield self.render_template('error.html',status_code = 'Error', status_message = 'You should log in through Salesforce')
            self.finish(html)

        user = yield self.login_user(userDict)
        next_url = self.get_next_url(user)
        if(not 'spawn' in next_url ):
            print('this is weird. It didnt go to spawn!')

        self.redirect(next_url)

    def get_token(self, signed_request):
        sign, payload = signed_request.split('.', 1)
        payload
        signature = hmac.new(
            b'ACA76D31C1FC230B34A5A9EE887C7121C5E1BA6B3C4526B2D1E3E52923A33D85',
            msg=payload.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        token = None
        if(base64.b64decode(sign) == signature):
            print('this is from salesforce!')
            token = dict()
            decodedContext = json.loads(base64.b64decode(payload))
            token['tkn'] = decodedContext['client']['refreshToken']
            token['user'] = decodedContext['userId']
        return token

class stensAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the user query parameter.
    """

    def get_handlers(self, app):
        return [
        (r'/login', stensAuthHandler),(r'/login2', stensAuthHandler2),
    ]
    @gen.coroutine
    def authenticate(self, handler, data):
        print('running authenicate')
        print(data)
        return {
        'name': data['name'],
        'auth_state': {
            'refreshToken': data['refreshToken']

        }
    }

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass inkspot data to spawner via environment variable"""

        auth_state = yield user.get_auth_state()
        print('prespawn in running')
        spawner.environment['testVar'] = 'tjenabena'
        if not auth_state:
        # auth_state not enabled
            print(auth_state)
            self.log.debug('auth_state not enabled')
            print('auth_state not enabled')
            return
        spawner.args = ['--NotebookApp.allow_origin=*']
        spawner.args = [ '--config=/home/shared_config/jupyter_notebook_config.py']
        spawner.environment['refreshToken'] = auth_state['refreshToken'] 
        
async def custom_pre_spawn_hook(spawner):
    auth_state = await spawner.user.get_auth_state()
    print(auth_state)
    print('this is from custom_pre_spawn_hook')
    if not auth_state:
        print('auth state is not working int he custom pre-spawn')
        auth_state = {'refreshToken' : 'stupid empty token'}
    spawner.environment['refreshToken'] = auth_state['refreshToken']
    #user_details = auth_state["oauth_user"]
