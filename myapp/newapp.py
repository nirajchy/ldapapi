from flask import Flask, render_template, flash, redirect, Response, request, session, abort, url_for
from ast import literal_eval
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode
import ldap
import sys, json, ast, crypt
import os
import re
import itertools
from flask import jsonify
import random
import getpass
import subprocess
import hashlib
import base64
import ldap.modlist
#import modlist
#from passlib.hash import pbkdf2_sha256
con = ldap.initialize('ldap://localhost:389')

# At this point, we're connected as an anonymous user
# If we want to be associated to an account
# you can log by binding your account details to your connection

con.simple_bind_s("cn=Manager,dc=example,dc=com", "password")

########## User Input Variable ####################################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'F34TF$($e34D'

@app.route('/')

def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return "Welcome to Ldap Admin Console <a href='/logout'>Logout</a>"

@app.route('/addu')
def addu():
        if session['logged_in'] == True:
                return render_template('form_submit.html')
        else:
                return home()

@app.route('/adduser', methods=['POST'])

def adduser():
	if request.method == 'POST':
	 user = request.form['username']
	 empid = request.form['empid']
	 mob = request.form['mobileno']
	 email = request.form['email']
	 pwd = request.form['password']
	 group = request.form['group']
	user = re.split('@', email)[0]

	E = empid.istitle()
	if E == False:
		empid = empid.upper()

	D = len(str(mob))
	if D < 10:
		print "You Have Enterd Wrong Mobile No"
		sys.exit(0)

	mail = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
	if mail == None:
		print('Bad email Syntax')
		raise ValueError('Bad Syntax')
	userid = random.sample(range(2000, 15000), 1)
	uid = str(userid[0])

	salt = os.urandom(4)
	h = hashlib.sha1("" + pwd +"")
	h.update(salt)
	#password = "{SSHA}" + encode(h.digest() + salt)
	#password = "password"
	password = base64.b64encode("" + pwd +"")
	if group == 'sasuser':
		gid = "514"
	elif group == 'jira_users':
		gid = "1001"
	#con = ldap.initialize('ldap://localhost:389')
	#con.simple_bind_s("cn=Manager,dc=example,dc=com", "password")
########## performing a simple ldap query ####################################
	ldap_base = "dc=example,dc=com"
	query = "(cn=" + user +")"
	result = con.search_s(ldap_base, ldap.SCOPE_SUBTREE, query)
	#if result != 0:
	#	return "result"
	dn = "cn=" + user +",ou=People,dc=example,dc=com"
	modlist = {
		   "objectClass": ["inetOrgPerson", "posixAccount", "shadowAccount"],
        	   "uid": ["" + user +""],
           	   "sn": ["" + user +""],
		   "givenName": ["" + user +""],
		   "uidNumber": ["" + uid +""],
		   "gidNumber": ["" + gid +""],
        	   "cn": ["" + user +""],
        	   "displayName": ["" + user +""],
	 	   "mail": ["" + email +""],
		   "userPassword": ["" + pwd +""],
   		   "mobile": ["" + mob +""],
	 	   "uid": ["" + empid +""],
		   "loginShell": ["/bin/bash"],
        	   "homeDirectory": ["/home/" + user +""]}
	print modlist
	cod = ast.literal_eval(json.dumps(modlist))
	#result = con.add_s(dn, ldap.modlist.addModlist(str(modlist)))
	var = checkUser("" + user +"") 
	print var
	if var == None:
		result = con.add_s(dn, ldap.modlist.addModlist(cod))
		#print result
		kn = "cn=" + group +",ou=Group,dc=example,dc=com"
		suser = "" + user +""
		pod = ast.literal_eval(json.dumps(suser))
		mod_attrs = [(ldap.MOD_ADD, "memberUid", pod )]
		tod = con.modify_s(kn, mod_attrs)
		#if result == "" && tod == "":
		return render_template('form_action.html', name="success")
	else:
		return render_template('form_action.html', name="Already Exists")
		
def checkUser(user):
        #con = ldap.initialize('ldap://localhost:389')
        #con.simple_bind_s("cn=Manager,dc=example,dc=com", "password")
        ldap_base = "dc=example,dc=com"
        query = "(cn=" + user +")"
        result = con.search_s(ldap_base, ldap.SCOPE_SUBTREE, query)
        for r in result:
                return r

@app.route('/cpw')
def cpw():
        if session['logged_in'] == True:
                return render_template('changePassword_submit.html')
        else:
                return home()

@app.route('/changePassword', methods=['POST'])

def changePassword():
	if request.method == 'POST':
	  username = request.form['username']
	  oldpassword = request.form['password']
	  newpassword = request.form['npassword']
	dn = "cn=" + username +",ou=People,dc=example,dc=com"
	old_value = {"userPassword": ["" + oldpassword +""]}
	new_value = {"userPassword": ["" + newpassword +""]}
	#modlist = ldap.modlist.modifyModlist(old_value, new_value)
	modlist = ldap.modlist.modifyModlist(old_value, new_value)
	con.modify_s(dn, modlist)

@app.route('/deleteuser', methods=['POST'])
def deleteUser():
	if request.method == 'POST':
	   username = request.json['username']
	   print username

@app.route('/login', methods=['POST'])

#def lconnect():
def login():
      if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        empid = request.form['empid']
        ldap_server = "localhost"
        ldap_port = "389"
        # the following is the user_dn format provided by the ldap server
        user_dn = "cn=" + username + ",ou=People,dc=example,dc=com"
        # adjust this to your base dn for searching
        base_dn = "dc=example,dc=com"
        connect = ldap.open(ldap_server)
        search_filter = "uid=" + empid
        try:
                # if authentication successful, get the full user data
		privileged_user = ["user1", "user2", "user3"]
		if username in privileged_user:
	        	connect.bind_s(user_dn, password)
        		result = connect.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)
		else:
			return home()
                # return all user data results
                session['logged_in'] = True
                return render_template('ldap_action.html', name="")
                connect.unbind_s()
        except ldap.LDAPError:
                connect.unbind_s()
                print "authentication error"
                #return render_template('ldap_action.html', name="Authentication Error")
                return home()

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()

if __name__ == '__main__':
	#app.secret_key = os.urandom(12)
	app.run(host="0.0.0.0", port=8081)
	#app.debug = True
	#app.run()
