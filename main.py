#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re
import fnmatch
from google.appengine.ext import db
from datetime import datetime, timedelta
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

allowed_routes = ["/new_post"]
# allowed_routes = ["/", "/login", "/signup", "/all_posts", "/blog/<id:\d+>"]

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

        if not self.user and self.request.path in allowed_routes:
            self.redirect('/login')
            return

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return cookie_val

    def get_user_by_name(self, username):
        user = db.GqlQuery("SELECT * from User WHERE uname = '%s'" % username)
        if user:
            return user.get()

    def login_user(self, user):
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    def set_secure_cookie(self, name, val):
        cookie_val = val
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def logout_user(self):
        self.set_secure_cookie('user_id', '')

class MainHandler(Handler):
    def render_front(self, user=""):
        blogs = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")
        self.render("home.html", blogs=blogs, user=user)


    def get(self):
        self.render_front(user = self.get_user_by_name)


class Login(Handler):
    def render_login_form(self, error=""):
        # t = jinja_env.get_template("login.html")
        self.render("login.html", error=error)

    def get(self):
        self.render_login_form()

    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        user = self.get_user_by_name(submitted_username)
        if not user:
            self.render_login_form(error = "Invalid username")
        elif submitted_password != user.pw or submitted_password == "":
        # elif not valid_pw(submitted_username, submitted_password, user.pw):
            self.render_login_form(error = "Invalid password")
        # elif not hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
        #     self.render_login_form(error = "Invalid password")
        else:
            # self.write("Welcome " + submitted_username + "" + user.pw)
            # self.write("Welcome " + headerZ)
            self.login_user(user)
            self.redirect("/")
            return


class Signup(Handler):
    uname_check = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    pw_check = re.compile(r"^.{3,20}$")

    def render_front(self, uname="", email="", errors={}):
        self.render("signup.html", uname=uname, email=email, errors=errors)

                    # error_uname=error_uname, error_pw=error_pw,
                    # error_vpw=error_vpw, error_email=error_email)

    def get(self):
        self.render("signup.html", errors={})

    def post(self):
        uname = self.request.get("username")
        pw = self.request.get("password")
        vpw = self.request.get("verify_password")
        email = self.request.get("email")

        error_uname = ""
        error_pw = ""
        error_vpw = ""
        error_email = ""

        errors = {}
        email_check = "*@*.*"
        error_check = False

        user_name = self.get_user_by_name(uname)
        if user_name:
            errors["error_existing_uname"] = "Existing Username. Please create a different Username."
            error_check = True
        if not (uname and self.uname_check.match(uname)):
            errors["error_uname"] = "Please enter a valid user name"
            error_check = True
        if not (pw and self.pw_check.match(pw)):
            errors["error_pw"] = "Please enter a valid password"
            error_check = True
        if pw != vpw and pw is not None and vpw is not None:
            errors["error_vpw"] = "Passwords do not match"
            error_check = True
        if email != "" and not fnmatch.fnmatch(email, email_check):
            errors["error_email"] = "Invalid email address"
            error_check = True
        if error_check is True:
            self.render_front(uname, email, errors=errors)
        else:
            a = User(uname=uname, pw=pw, email=email)
            a.put()
            self.login_user(a)
            time.sleep(1)
            self.redirect("/")
            # self.response.headers.add_header()
            # self.write("You have successfully signed up!")

class User(db.Model):
    uname = db.StringProperty(required=True)
    pw = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class Blog(db.Model):
    title = db.StringProperty(required=True)
    blog = db.TextProperty(required=True)
    created_by = db.StringProperty(required=True)
    created = db.DateTimeProperty(required=True)

class NewPost(Handler):
    def render_front(self, error="", msg="", entry_title="", entry_blog=""):
        self.render("new_post.html", error=error, msg=msg, entry_title=entry_title, entry_blog=entry_blog)

    def get(self):
        self.render("new_post.html", error="", msg="", entry_title="", entry_blog="")

    def post(self):
        title = self.request.get("title")
        blog = self.request.get("blog")
        created = datetime.today() + timedelta(hours=-6)
        msg = ""
        entry_title = self.request.get('title')
        entry_blog = self.request.get('blog')

        user_id = self.request.cookies.get('user_id', '')
        if title and blog:
            a = Blog(title=title, blog=blog, created_by=user_id, created=created)
            a.put()
            time.sleep(1)
            self.redirect("/")
            # msg = "You have successfully submitted a new post!"
            # self.render_front(msg)
        else:
            error = "Submit a title and blog post."
            self.render_front(error, msg, entry_title, entry_blog)

class Logout(Handler):
    def get(self):
        self.logout_user()
        self.redirect("/login")
        return

class ViewPostHandler(Handler):
    def render_blog(self, id=""):
        # for b in db.GqlQuery("SELECT * FROM User"):
        #     for a in db.GqlQuery("SELECT * FROM Blog WHERE ID")
        blogs = db.GqlQuery("SELECT * FROM Blog Where created_by = '%s'"
                            " ORDER BY created DESC LIMIT 5" % id)
        users = db.GqlQuery("SELECT * FROM User Where __key__ = KEY('User', " + id + ")")
        u = users.get()
        self.render("blog.html", blogs=blogs, id=id, users=u.uname)
        # self.write(id)

    def get(self, id):
        self.render_blog(id)

class AllPosts(Handler):
    def render_allposts(self):
        # blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 5")

        blogs = db.GqlQuery("SELECT * FROM Blog"
                            " ORDER BY created DESC LIMIT 5")
        users = db.GqlQuery("SELECT * FROM User")
        self.render("all_posts.html", blogs=blogs, users=users)

    def get(self):
        self.render_allposts()

class ViewSinglePost(Handler):
    def render_blog(self, id=""):
        blogs = db.GqlQuery("SELECT * FROM Blog Where __key__  = KEY('Blog', " + id + ")")
        b = blogs.get()
        users = db.GqlQuery("SELECT * FROM User Where __key__ = KEY('User', " + b.created_by + ")")
        u = users.get()
        self.render("blog.html", blogs=blogs, id=id, users=u.uname)
        # self.write("test")

    def get(self, id):
        self.render_blog(id)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', Login),
    ('/signup', Signup),
    ('/new_post', NewPost),
    ('/logout', Logout),
    ('/all_posts', AllPosts),
    webapp2.Route('/blog/<id:\d+>', ViewPostHandler),
    webapp2.Route('/post/<id:\d+>', ViewSinglePost)
], debug=True)
