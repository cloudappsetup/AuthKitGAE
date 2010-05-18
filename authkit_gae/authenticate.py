from authkit.authenticate import AuthKitUserSetter, AuthKitAuthHandler, \
    AuthKitConfigError, get_authenticate_function, strip_base
from authkit.authenticate.multi import MultiHandler, status_checker
from paste.request import construct_url
from google.appengine.api.users import create_login_url, create_logout_url, \
    get_current_user

class GoogleAccountHandler(AuthKitAuthHandler):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        return_url = construct_url(environ)
        login_url = create_login_url(return_url)
        
        start_response('302 Found', [
            ('Location', login_url),
            ('Content-Type', 'text/plain'),
            ('Content-Length','0'),
        ])
        return ['redirecting to %s' % login_url]

class GoogleUserSetter(AuthKitUserSetter):
    def __init__(self,
        app,
        signout_path=None,
        admin_role=None,
    ):
        self.app = app
        self.signout_path = signout_path
        self.admin_role = admin_role
    
    def __call__(self, environ, start_response):
        user = get_current_user()
        if user:
            environ['REMOTE_USER'] = user.email()
            
            if self.signout_path and environ.get('PATH_INFO') == self.signout_path:
                return_url = construct_url(environ)
                logout_url = create_logout_url(return_url)
                
                start_response('302 Found', [
                    ('Location', logout_url),
                    ('Content-Type', 'text/plain'),
                    ('Content-Length','0'),
                ])
                return ['redirecting to %s' % logout_url]
        
        if self.admin_role:
            environ['authkit.google.adminrole'] = self.admin_role
        
        return self.app(environ, start_response)

def load_google_config(
    app, 
    auth_conf, 
    app_conf,
    global_conf,
    prefix,
):
    authenticate_conf = strip_base(auth_conf, 'authenticate.')
    app, authfunc, users = get_authenticate_function(
        app, 
        authenticate_conf, 
        prefix=prefix+'authenticate.', 
        format='basic'
    )
    
    auth_handler_params = {
        'authfunc': authfunc,
    }
    
    user_setter_params = {
        'signout_path':  auth_conf.get('signoutpath', None),
        'admin_role': auth_conf.get('adminrole', None),
    }

    return app, auth_handler_params, user_setter_params

def make_handler(
    app, 
    auth_conf, 
    app_conf=None,
    global_conf=None,
    prefix='authkit.method.google.', 
):
    app, auth_handler_params, user_setter_params = load_google_config(
        app, 
        auth_conf, 
        app_conf,
        global_conf,
        prefix,
    )
    app = MultiHandler(app)
    app.add_method(
        'google',
        GoogleAccountHandler
    )
    app.add_checker('google', status_checker)
    
    app = GoogleUserSetter(app, **user_setter_params)
    
    return app

