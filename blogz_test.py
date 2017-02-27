import random, string, hashlib, hmac


# SECRET = 'czUv86iAN9GXA3MT'
# def hash_str(s):
#     return hmac.new(SECRET,s).hexdigest()
#
# print(hash_str("Hello"))

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s

def make_secure_val(s):
    return '%s|%s' % (s, hash_str(s))

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

SECRET = 'czUv86iAN9GXA3MT'
print(check_secure_val("hello"))


def set_secure_cookie(self, name, val):
    """ Adds a secure name-value pair cookie to the response """
    # cookie_val = hashutils.make_secure_val(val)
    # self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
    self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, val))
