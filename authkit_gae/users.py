from authkit.users import AuthKitNoSuchUserError, AuthKitNoSuchRoleError, \
    AuthKitNoSuchGroupError, AuthKitError, Users
from paste.util.import_string import eval_import
from authkit_gae.models import *
from google.appengine.ext import db
from google.appengine.api.users import get_current_user, is_current_user_admin

class UsersFromDatastore(Users):
    api_version = 0.4

    def __init__(self, environ, data=None, encrypt=None):
        if encrypt is None:
            def encrypt(password):
                return password
        self.encrypt = encrypt
        self.environ = environ
        
        self.adminrole = environ.get('authkit.google.adminrole', None)
        if self.adminrole:
            self.adminrole = self.adminrole.lower()
        
        # load the user_model given in the data:
        if data and isinstance(data, (str, unicode)):
            self.user_model = eval_import(data)
        else:
            self.user_model = BaseUser

    # Create Methods
    def user_create(self, username, password, group=None):
        """
        Create a new user with the username, password and group name specified.
        """
        if self.user_exists(username):
            raise AuthKitError("User %r already exists" % username)
        
        if group is not None:
            group = UserGroup.all().filter("name =", group.lower()).get()
            
            if group is None:
                raise AuthKitNoSuchGroupError("There is no such group %r" % group)
        
        if password:
            password = self.encrypt(password)
        usr = self.user_model(username=username.lower(), password=password)
        if group:
            usr.group = group
        usr.put()

    def role_create(self, role):
        """
        Add a new role to the system
        """
        if ' ' in role:
            raise AuthKitError("Roles cannot contain space characters")
        if self.role_exists(role):
            raise AuthKitError("Role %r already exists" % role)
        
        UserRole(name=role.lower()).put()

    def group_create(self, group):
        """
        Add a new group to the system
        """
        if ' ' in group:
            raise AuthKitError("Groups cannot contain space characters")
        if self.group_exists(group):
            raise AuthKitError("Group %r already exists" % group)
        
        UserGroup(name=group.lower()).put()
        
    # Delete Methods
    def user_delete(self, username):
        """
        Remove the user with the specified username 
        """
        
        usr = self.user_model.all().filter("username =", username.lower()).get()
        
        if usr is None:
            raise AuthKitError("There is no such user %r" % username)
        else:
            usr.delete()
        
    def role_delete(self, role):
        """
        Remove the role specified. Rasies an exception if the role is still in use. 
        To delete the role and remove it from all existing users use ``role_delete_cascade()``
        """
        if self.adminrole and role.lower() == self.adminrole:
            raise AuthKitError("Cannot delete magic role %r" % role)
        
        r = UserRole.all().filter("name =", role.lower()).get()
        if r is None:
            raise AuthKitError("There is no such role %r" % role)
        
        q = self.user_model.all().filter("roles =", r.key())
        if q.count() > 0:
            raise AuthKitError("The role is still being used and therefore cannot be deleted" % role)
        
        r.delete()
        
    def group_delete(self, group):
        """
        Remove the group specified. Rasies an exception if the group is still in use. 
        To delete the group and remove it from all existing users use ``group_delete_cascade()``
        """
        
        grp = UserGroup.all().filter("name =", group.lower()).get()
        if grp is None:
            raise AuthKitError("There is no such group %r" % group)
        
        q = self.user_model.all().filter("group =", grp.key())
        if q.count() > 0:
            raise AuthKitError("The group %r is still being used and therefore cannot be deleted" % group)
        
        grp.delete()
        
    # Delete Cascade Methods
    def role_delete_cascade(self, role):
        """
        Remove the role specified and remove the role from any users who used it
        """
        if self.adminrole and role.lower() == self.adminrole:
            raise AuthKitError("Cannot delete magic role %r" % role)
        
        r = UserRole.all().filter("name =", role.lower()).get()
        if r is None:
            raise AuthKitError("There is no such role %r" % role)
        
        users = self.user_model.all().filter("roles =", r.key())
        for usr in users:
            usr.roles.remove(r.key())
        db.put(users)
        
        r.delete()
        
    def group_delete_cascade(self, group):
        """
        Remove the group specified and remove the group from any users who used it
        """
        grp = UserGroup.all().filter("name =", group.lower()).get()
        if grp is None:
            raise AuthKitError("There is no such group %r" % group)
        
        users = self.user_model.all().filter("group =", grp.key())
        for usr in users:
            usr.group = None
        db.put(users)
        
        grp.delete()
        
    # Existence Methods
    def user_exists(self, username):
        """
        Returns ``True`` if a user exists with the given username, ``False`` otherwise. Usernames are case insensitive.
        """
        return self.user_model.all().filter("username =", username.lower()).count() > 0
        
    def role_exists(self, role):
        """
        Returns ``True`` if the role exists, ``False`` otherwise. Roles are case insensitive.
        """
        if self.adminrole and role.lower() == self.adminrole:
            return True
        
        return UserRole.all().filter("name =", role.lower()).count() > 0
        
    def group_exists(self, group):
        """
        Returns ``True`` if the group exists, ``False`` otherwise. Groups are case insensitive.
        """
        return UserGroup.all().filter("name =", group.lower()).count() > 0
        
    # List Methods
    def list_roles(self):
        """
        Returns a lowercase list of all role names ordered alphabetically
        """
        roles = UserRole.all().order("name")
        return [r.name for r in roles]
        
    def list_users(self):
        """
        Returns a lowecase list of all usernames ordered alphabetically
        """
        users = self.user_model.all().order("username")
        return [usr.username for usr in users]
        
    def list_groups(self):
        """
        Returns a lowercase list of all groups ordered alphabetically
        """
        groups = UserGroup.all().order("name")
        return [grp.name for grp in groups]

    # User Methods
    def user(self, username):
        """
        Returns a dictionary in the following format:

        .. code-block :: Python
        
            {
                'username': username,
                'group':    group,
                'password': password,
                'roles':    [role1,role2,role3... etc]
            }

        The role names are ordered alphabetically
        Raises an exception if the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        group = None
        if usr.group:
            group = usr.group.name
        
        roles = [r.name for r in UserRole.get(usr.roles)]
        if self.adminrole:
            logged = get_current_user()
            if logged and logged.email().lower() == usr.username:
                if is_current_user_admin():
                    roles.append(self.adminrole)
        roles.sort()
        
        return {
            'username': usr.username,
            'group':    group,
            'password': usr.password,
            'roles':    roles,
        }
        
    def user_roles(self, username):
        """
        Returns a list of all the role names for the given username ordered alphabetically. Raises an exception if
        the username doesn't exist.
        """
        usr = self.user(username)
        return usr['roles']
        
    def user_group(self, username):
        """
        Returns the group associated with the user or ``None`` if no group is associated.
        Raises an exception is the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        return usr.group.name
        
    def user_password(self, username):
        """
        Returns the password associated with the user or ``None`` if no password exists.
        Raises an exception is the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        return usr.password
        
    def user_has_role(self, username, role):
        """
        Returns ``True`` if the user has the role specified, ``False`` otherwise. Raises an exception if the user doesn't exist.
        """
        return role.lower() in self.user_roles(username)
        
    def user_has_group(self, username, group):
        """
        Returns ``True`` if the user has the group specified, ``False`` otherwise. The value for ``group`` can be ``None`` to test that the user doesn't belong to a group. Raises an exception if the user doesn't exist.
        """
        return group.lower() == self.user_group(username)

    def user_has_password(self, username, password):
        """
        Returns ``True`` if the user has the password specified, ``False`` otherwise. Passwords are case sensitive.
        Raises an exception if the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        return usr.password == self.encrypt(password)

    def user_set_username(self, username, new_username):
        """
        Sets the user's username to the lowercase of new_username. 
        Raises an exception if the user doesn't exist or if there is already a user with the username specified by ``new_username``.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        if self.user_exists(new_username.lower()):
            raise AuthKitError("A user with the username %r already exists" % username)
        
        usr.username = new_username.lower()
        usr.put()
        
    def user_set_group(self, username, group, add_if_necessary=False):
        """
        Sets the user's group to the lowercase of ``group`` or ``None``. If the group doesn't exist and ``add_if_necessary`` is ``True`` the group will also be added. Otherwise an ``AuthKitNoSuchGroupError`` will be raised.
        Raises an exception if the user doesn't exist.
        """
        if group is None:
            return self.user_remove_group(username)
        
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        grp = UserGroup.all().filter("name =", group.lower()).get()
        
        if grp is None:
            if not add_if_necessary:
                raise AuthKitNoSuchGroupError("No such group %r" % group)
            grp = UserGroup(name=group.lower())
        
        usr.group = grp
        usr.put()
        
    def user_add_role(self, username, role, add_if_necessary=False):
        """
        Sets the user's role to the lowercase of ``role``. If the role doesn't exist and ``add_if_necessary`` is ``True`` the role will also be added. Otherwise an ``AuthKitNoSuchRoleError`` will be raised.
        Raises an exception if the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        if self.adminrole and role.lower() == self.adminrole:
            raise AuthKitError("Cannot assign magic role %r explicitly" % role)
        
        r = UserRole.all().filter("name =", role.lower()).get()
        if r is None:
            if not add_if_necessary:
                raise AuthKitNoSuchRoleError("No such role %r" % role)
            r = UserRole(name=role.lower())
            r.put()
        
        if r.key() not in usr.roles:
            usr.roles.append(r.key())
            usr.put()
        
    def user_remove_role(self, username, role):
        """
        Removes the role from the user specified by ``username``. Raises an exception if the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        if self.adminrole and role.lower() == self.adminrole:
            raise AuthKitError("Cannot remove magic role %r" % role)
        
        r = UserRole.all().filter("name =", role.lower()).get()
        if r is None:
            raise AuthKitNoSuchRoleError("No such role %r" % role)
        
        
        if r.key() not in usr.roles:
            raise AuthKitError("No role %r found for user %r" % (role, username))
        
        usr.roles.remove(r.key())
        usr.put()

    def user_remove_group(self, username):
        """
        Sets the group to ``None`` for the user specified by ``username``. Raises an exception if the user doesn't exist.
        """
        usr = self.user_model.all().filter("username =", username.lower()).get()
        if usr is None:
            raise AuthKitNoSuchUserError("No such user %r" % username)
        
        usr.group = None
        usr.put()

