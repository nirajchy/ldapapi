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

#-con = ldap.initialize('ldap://localhost:389')
ldap_ip="localhost"
con = ldap.initialize(str("ldap://"+ldap_ip))
connect = ldap.initialize(str("ldap://"+ldap_ip))
ldap_base2 = "dc=example,dc=com"
grp_names_list=list()
priviledge=False
ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)
l = ldap.initialize("ldap://"+ldap_ip , trace_level=2)
# At this point, we're connected as an anonymous user
# If we want to be associated to an account
# you can log by binding your account details to your connection

con.simple_bind_s("cn=Manager,dc=example,dc=com", "cndy525//")
connect.simple_bind_s("cn=Manager,dc=example,dc=com", "cndy525//")


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
        if session['logged_in'] == True and priviledge==True:
                return render_template('form_submit.html', priviledge=str(priviledge))
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
#def adduser(user,empid,mobileno,email,password,group):
    user = re.split('@', email)[0]

    E = empid.istitle()
    if E == False:
        empid = empid.upper()

    D = len(str(mob))
    if D < 10:
        print "You Have Entered Wrong Mobile No"
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
    if group == 'group1':
        gid = "002"
    elif group == 'group2':
        gid = "001"
########## performing a simple ldap query ####################################
    query = "(cn=" + user +")"
    result = con.search_s(ldap_base2, ldap.SCOPE_SUBTREE, query)
    #if result != 0:
    #   return "result"
    dn = "cn=" + user +",ou=People,"+ldap_base2
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
        kn = "cn=" + group +",ou=Group,"+ldap_base2
        suser = "" + user +""
        pod = ast.literal_eval(json.dumps(suser))
        mod_attrs = [(ldap.MOD_ADD, "memberUid", pod )]
        tod = con.modify_s(kn, mod_attrs)
        #if result == "" && tod == "":
        return render_template('form_action.html', name="success", priviledge=str(priviledge))
    else:
        return render_template('form_action.html', name="Already Exists", priviledge=str(priviledge))
        
def checkUser(user):
        query = "(cn=" + user +")"
        result = con.search_s(ldap_base2, ldap.SCOPE_SUBTREE, query)
        for r in result:
                return r

@app.route('/cpw')
def cpw():
        if session['logged_in'] == True and priviledge==True:
                return render_template('changePassword_submit.html')
        else:
                return home()

@app.route('/changePassword', methods=['POST'])

def changePassword():
    if request.method == 'POST':
      username = request.form['username']
      oldpassword = request.form['password']
      print oldpassword
      newpassword = request.form['npassword']
    dn =str("cn=" + username +",ou=People,"+ldap_base2)
    old_value = {"userPassword": ["" + oldpassword +""]}
    new_value = {"userPassword": ["" + newpassword +""]}
    #modlist = ldap.modlist.modifyModlist(old_value, new_value)
    modlist = ldap.modlist.modifyModlist(old_value, new_value)
    con.modify_s(dn, modlist)

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
        user_dn = "cn=" + username + ",ou=People,"+ldap_base2
        print user_dn
        # adjust this to your base dn for searching
        #        con = ldap.open(ldap_server)
        global grp_names_list
        global priviledge
        priviledge=False
        search_filter = "uid=" + empid
        try:
                    # if authentication successful, get the full user data
			# List of privileged users
            privileged_users = ["user1", "user2", "user3", "user4", "user5"]
            if username in privileged_users:
                    connect.bind_s(user_dn, password)
                    result = connect.search_s(ldap_base2, ldap.SCOPE_SUBTREE, search_filter)
                    priviledge=True
            else:
                return home()
                    # return all user data results
            del grp_names_list[ : ]
            grp_names_list=fetch_grp_list()
            session['logged_in'] = True
            return render_template('ldap_action.html', name="",priviledge=str(priviledge))
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

####################################################################################### added code below


#Function to check employee id pattern
def checkEmpIDpattern(empid):
    if(len(empid)>2 and len(empid)<7):
        if(empid[0]=='C' or empid[0]=='T'):
            if(empid[1:].isnumeric()):
                return True
    return False

def filter_priviledged(glist):
    print "inside filter function"
    glist2=glist[:]
    for group_name in glist:
        if not("fqa" in group_name or "svn" in group_name):
            glist2.remove(group_name)
    return glist2


#Function to get the existing group on LDAP
def fetch_grp_list():
    glist=list()
    ldap_base3=str("ou=Group,"+ldap_base2)
    result = con.search_s(ldap_base3, ldap.SCOPE_SUBTREE)
    for tup in result:
        result = con.search_s(ldap_base3, ldap.SCOPE_SUBTREE)
        if len(ldap.dn.explode_dn(tup[0]))==4:     
            glist.append((ldap.dn.explode_dn(tup[0],[ldap.DN_PRETTY]))[0])
    glist.remove("jira_users")
    glist.remove("sasuser")
    glistfil=glist
    if not priviledge:
        glistfil=filter_priviledged(glist[:])
    print "filter grp names list"
    print glistfil
    return glistfil

#include this function in main function


#Function to get distinguished name of employee, which is entered in svn viewvc group 
def dn_viewvc(empid):
    ldap_base3=str("ou=People,"+ldap_base2)
    query="(uid={0})".format(empid)
    attrib=["dn"]
    result=con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL, query, attrib)
    return result[0][0]

#check if employee has an ldap account
def check_employee_in_ldap(empid):
    ldap_base3=str("ou=People,"+ldap_base2)
    query="(uid={0})".format(empid)
    
    result=con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL, query)
    return result


#Add an employee to an existing group
def entryAdd(group_name,empid):
    ldap_base3=str("ou=Group,"+ldap_base2)
    query = "(cn="+str(group_name)+")"
    result = con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL,query)
    if not checkinGroup(empid,group_name):
        kn = "cn=" + group_name +",ou=Group,"+ldap_base2
        user = "" + empid +""
        pod = ast.literal_eval(json.dumps(user))
        mod_attrs = [(ldap.MOD_ADD, "memberUid", pod )]
        tod = con.modify_s(kn, mod_attrs)

#Delete an employee to an existing group
def entryDel(group_name,empid):
    ldap_base3=str("ou=Group,"+ldap_base2)
    query = "(cn="+str(group_name)+")"
    result = con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL,query)
    if checkinGroup(empid,group_name):
        kn = "cn=" + group_name +",ou=Group,"+ldap_base2
        user = "" + empid +""
        pod = ast.literal_eval(json.dumps(user))
        mod_attrs = [(ldap.MOD_DELETE, "memberUid", pod )]
        tod = con.modify_s(kn, mod_attrs)

#Replacing employee2 by employee1
def entryMod(group_name,empid1,empid2):
    ldap_base3=str("ou=Group,"+ldap_base2)
    query = "(cn="+str(group_name)+")"
    result = con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL,query)
    if not checkinGroup(empid1,group_name):
        kn = "cn=" + group_name +",ou=Group,"+ldap_base2
        user = "" + empid1 +""
        pod = ast.literal_eval(json.dumps(user))
        mod_attrs = [(ldap.MOD_ADD, "memberUid", pod )]
        tod = con.modify_s(kn, mod_attrs)
        print tod
    if checkinGroup(empid2,group_name):
        kn = "cn=" + group_name +",ou=Group,"+ldap_base2
        user = "" + empid2 +""
        pod = ast.literal_eval(json.dumps(user))
        mod_attrs = [(ldap.MOD_DELETE, "memberUid", pod )]
        tod = con.modify_s(kn, mod_attrs)


def form_HTML_page(motive):
    count=0
    rows=""

    for group in grp_names_list:
        if count%2==0:
            rows=str(rows+"<tr>")
        rows=str(rows+'''
             <td style="padding-left:50px">   
             <label><input type="checkbox"; style="width: 15px; height: 15px;" name="box_list" value={name}  >
             <div class="view div22" style=" display: inline-block; border-radius: 4px;
             font-family: "arial-black";font-size: 14px; color:red;  padding: 8px 12px; cursor: pointer; ">{name}</div>
             </label></td>
            '''.format(name=group,name_justified=group.ljust(10)))
        
        if count%2==1:
            rows=str(rows+"</tr>")
        count+=1
        #check_box_list.append(str("ck"+str(count)))
    if count%2==1:
            rows=str(rows+"</tr>")

    return render_template('addgroup.html', table_rows=rows, motive=motive, priviledge=str(priviledge))

@app.route('/addg')
def add_g():
    if session['logged_in'] == True:
        return form_HTML_page(motive="add")
    else:
        return home()

@app.route('/delg')
def del_g():
    if session['logged_in'] == True:
        return form_HTML_page(motive="del")
    else:
        return home()

@app.route('/modg')
def mod_g():
    if session['logged_in'] == True:
        return form_HTML_page(motive="mod")
    else:
        return home()


def checkinGroup(empid,group_name):
    ldap_base3=str("ou=Group,"+ldap_base2)
    query = "(cn="+str(group_name)+")"
    attrib=["memberUid"]
    result = con.search_s(ldap_base3, ldap.SCOPE_ONELEVEL,query,attrib)
    try:
        if empid in result[0][1]['memberUid']:
            return True
    except KeyError as group_empty:
        return False
    return False


@app.route('/delgrp',methods = ['POST'])
def del_grp():
    if request.method == 'POST':
        print "Enter del_grp................."
        empid=request.form["empid"]
        if checkEmpIDpattern(empid)==False:
            return render_template('form_action.html', name="Enter proper employee id", priviledge=str(priviledge))
        
        result_page=""
        check_box_list=request.form.getlist("box_list")
        no_of_groups=len(check_box_list)
        for i in range(0,no_of_groups):
            group_name=check_box_list[i]
            if group_name:
                result_page=str(result_page+"<br>  Deletion of "+str(empid)+ " from "+str(group_name)+" : ")
                if group_name=="svn":
                    if not checkinGroup(dn_viewvc(empid),group_name):
                        result_page=str(result_page + " Already absent!")
                    else:
                        print "Caught group name svn"
                        entryDel(group_name, dn_viewvc(empid))
                        result_page=str(result_page + "Done")
                else:
                    if not checkinGroup(empid, group_name):
                        result_page=str(result_page + " Already absent!")
                    else:
                        entryDel(group_name, empid)
                        result_page=str(result_page + "Done")
        if request.form.getlist("presence"):
            result_page=str(result_page+'''<div align="center"<br><br>Employee present in following groups<br>''')
            for group_name in grp_names_list:
                if checkinGroup(empid,group_name):
                    result_page=str(result_page + " | " + group_name)
            result_page=str(result_page+'''</div>''')
        return render_template('form_action.html', name=result_page, priviledge=str(priviledge))



@app.route('/addgrp',methods = ['POST'])
def add_grp():
    if request.method == 'POST':
        empid=request.form["empid"]
        if checkEmpIDpattern(empid)==False:
            return render_template('form_action.html', name="Enter proper employee id", priviledge=str(priviledge))

        if not check_employee_in_ldap(empid):
            return render_template('form_action.html', name="No user found", priviledge=str(priviledge))

        result_page=""
        check_box_list=request.form.getlist("box_list")
        no_of_groups=len(check_box_list)
        #for i in range(0,no_of_groups):
        #    check_box_list.append(str("ck"+str(i)))
        for i in range(0,no_of_groups):
            #checkbox_name=check_box_list[i]
            group_name=check_box_list[i]
            if not checkinGroup(empid,group_name):
                if group_name:
                    try:
                        result_page=str(result_page+"<br>  Addition of "+str(empid)+ " to "+str(group_name)+" : ")
                        if group_name=="svn":
                            entryAdd(group_name, dn_viewvc(empid))
                            result_page=str(result_page + "Done")
                        else:
                            entryAdd(group_name, empid)
                            result_page=str(result_page + "Done")
                    except ldap.TYPE_OR_VALUE_EXISTS as user_exists:
                        result_page=str(result_page + "<b>Already present !</b>")
            else:
                result_page=str(result_page + "<b>Already present!</b>")
                return render_template('form_action.html', name=result_page, priviledge=str(priviledge))
        if request.form.getlist("presence"):
            result_page=str(result_page+'''<div align="center"<br><br>Employee present in following groups<br>''')
            for group_name in grp_names_list:
                if checkinGroup(empid,group_name):
                    result_page=str(result_page + " | " + group_name)
            result_page=str(result_page+'''</div>''')
        return render_template('form_action.html', name=result_page, priviledge=str(priviledge))


@app.route('/modgrp',methods = ['POST'])
def mod_grp():
    if request.method == 'POST':
        empid1=request.form["empid1"]
        empid2=request.form["empid2"]
        if checkEmpIDpattern(empid1)==False:
            return render_template('form_action.html', name="Enter proper employee id", priviledge=str(priviledge))

        if not check_employee_in_ldap(empid1):
            return render_template('form_action.html', name=str("No user found in ldap:"+str(empid1)), priviledge=str(priviledge))

        result_page=""
        if empid1==empid2:
            result_page=str(result_page+"<br>Enter different employee id's")
            return render_template('form_action.html', name=result_page, priviledge=str(priviledge))
        check_box_list=request.form.getlist("box_list")
        no_of_groups=len(check_box_list)
        #for i in range(0,no_of_groups):
        #    check_box_list.append(str("ck"+str(i)))
        for i in range(0,no_of_groups):
            #checkbox_name=check_box_list[i]
            group_name=check_box_list[i]
            if group_name:
                result_page=str(result_page+"<br>  Replacing  "+str(empid2)+ " by "+str(empid1)+" in "+str(group_name)+" : ")
                if group_name=="svn":
                    if checkinGroup(dn_viewvc(empid1),group_name):
                        result_page=str(result_page + str(empid1)+" is preset in group!")
                    elif not checkinGroup(dn_viewvc(empid2),group_name):
                        result_page=str(result_page +str(empid2)+ " Not found in group!")
                    else:
                        entryMod(group_name, dn_viewvc(empid1),dn_viewvc(empid2))
                        result_page=str(result_page + "Done")
                else:
                    if checkinGroup(empid1, group_name):
                        result_page=str(result_page+ str(empid1)+ " is present in group!")
                    elif not checkinGroup(empid2, group_name):
                        result_page=str(result_page +str(empid2)+ " Not found in group!")
                    else:
                        entryMod(group_name, empid1,empid2)
                        result_page=str(result_page + "Done")

        if request.form.getlist("presence"):
            result_page=str(result_page+'''<div align="center"<br><br>Employee present in following groups<br>''')
            for group_name in grp_names_list:
                if checkinGroup(empid1,group_name):
                    result_page=str(result_page + " | " + group_name)
            result_page=str(result_page+'''</div>''')
        return render_template('form_action.html', name=result_page, priviledge=str(priviledge))

#if __name__ == '__main__':
#    app.run(debug = True)

   
##if __name__ == '__main__':
#    #app.secret_key = os.urandom(12)
##   app.run(host="0.0.0.0", port=8081)
#    #app.debug = True
#    #app.run()
