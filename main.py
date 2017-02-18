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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainHandler(Handler):
    def render_front(self):
        self.render("home.html")

    def get(self):
        self.render_front()


class Login(Handler):
    def get(self):
        self.render("login.html")


class Signup(Handler):
    uname_check = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    pw_check = re.compile(r"^.{3,20}$")

    def render_front(self, uname="", email="", error_uname="", error_pw="", error_vpw="", error_email=""):
        self.render("signup.html", uname=uname, email=email, error_uname=error_uname, error_pw=error_pw,
                    error_vpw=error_vpw, error_email=error_email)

    def get(self):
        self.render("signup.html")

    def post(self):
        uname = self.request.get("username")
        pw = self.request.get("password")
        vpw = self.request.get("verify_password")
        email = self.request.get("email")

        error_uname = ""
        error_pw = ""
        error_vpw = ""
        error_email = ""

        email_check = "*@*.*"
        error_check = False
        if not (uname and self.uname_check.match(uname)):
            error_uname = "Please enter a valid user name"
            error_check = True
        if not (pw and self.pw_check.match(pw)):
            error_pw = "Please enter a valid password"
            error_check = True
        if pw != vpw and pw is not None and vpw is not None:
            error_vpw = "Passwords do not match"
            error_check = True
        if email != "" and not fnmatch.fnmatch(email, email_check):
            error_email = "Invalid email address"
            error_check = True
        if error_check is True:
            self.render_front(uname, email, error_uname, error_pw, error_vpw, error_email)
        else:
            a = NewUser(uname=uname, pw=pw, email=email)
            a.put()
            self.write("You have successfully signed up!")


class NewUser(db.Model):
    uname = db.StringProperty(required=True)
    pw = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', Login),
    ('/signup', Signup)
], debug=True)
