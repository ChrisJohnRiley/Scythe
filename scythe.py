#! /usr/bin/env python
# -*- coding: utf-8 -*-

#

"""
    scythe: account enumerator

    Account Enumerator is designed to make it simple to perform account
    enumeration as part of security testing. The framework offers the ability
    to easily create new modules (XML files) and speed up the process of testing.

    This tool was created with 2 main use cases in mind:

    - The ability to test a range of email addresses across a range of sites (e.g.
        social media, blogging platforms, etc...) to find where those targets have
        active accounts. This can be useful in a social engineering test where you
        have email accounts for a company and want to list where these users have
        used their work email for 3rd party web based services.

    - The ability to quickly create a custom testcase module and use it to enumerate
        for a list of active accounts. Using either a list of know usernames, email
        addresses, or a dictionary of common account names.

    This program is released as is and is not designed to be used to test again sites
    where you do not have permission. Any modules provided are for demonstration purposes
    and may breach end user license agreements if used against a site. Your mileage may
    vary... be responsible!

    External module depenancies: none

"""

import os
import re
import signal
import urllib2
import string
import textwrap
import sys
import traceback
from random import Random
from optparse import OptionParser, SUPPRESS_HELP
from array import *
from xml.dom.minidom import parse

__author__ = 'Chris John Riley'
__license__ = 'GPL'
__version__ = '0.1.3'
__codename__ = 'Lazy Lizard'
__date__ = '10 September 2012'
__maintainer__ = 'ChrisJohnRiley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'

modules = []
accounts = []
success = []

def logo():
    # because ASCII-art is the future!

    logo = '''
                                                                                        ,,
                                                                                 mm   `7MM
                                                                                 MM     MM
                                                    ,pP"Ybd  ,p6"bo `7M'   `MF'mmMMmm   MMpMMMb.  .gP"Ya
                                                    8I   `" 6M'  OO   VA   ,V    MM     MM    MM ,M'   Yb
                                                    `YMMMa. 8M         VA ,V     MM     MM    MM 8M""""""
                                                    L.   I8 YM.    ,    VVV      MM     MM    MM YM.    ,
                                                    M9mmmP'  YMbmd'     ,V       `Mbmo.JMML  JMML.`Mbmmd'
                                                                       ,V
                                                                    OOb"      ::: account harvester :::'''

    # add version, codename and maintainer to logo
    print logo
    print string.rjust('ver ' + __version__ + ' (' + __codename__ + ')', 102)
    print string.rjust(__maintainer__, 101)

def extract_module_data(module_dom):
    # extract module information from the provided dom

    module_xml = []
    print "\n",
    for each in module_dom:
        try:
            xmlData = {}
            xmlData['name'] = each.getElementsByTagName('name')[0].firstChild.nodeValue
            # set URL - prepend http:// if not present in string
            if not each.getElementsByTagName('url')[0].firstChild.nodeValue.startswith('http'):
                xmlData['url'] = 'http://' + each.getElementsByTagName('url')[0].firstChild.nodeValue
            else:
                xmlData['url'] = each.getElementsByTagName('url')[0].firstChild.nodeValue
            xmlData['method'] = each.getElementsByTagName('method')[0].firstChild.nodeValue
            # set POST Parameters if set in the module XML
            if each.getElementsByTagName('postParameters')[0].firstChild:
                xmlData['postParameters'] = each.getElementsByTagName('postParameters')[0].firstChild.nodeValue
            else:
                xmlData['postParameters'] = ''
            # set headers if set in the module XML
            if each.getElementsByTagName('headers')[0].firstChild:
                xmlData['headers'] = each.getElementsByTagName('headers')[0].firstChild.nodeValue.split(",")
            else:
                xmlData['headers'] = ''
            # set request cookie if set in the module XML
            if each.getElementsByTagName('requestCookie')[0].firstChild:
                xmlData['requestCookie'] = each.getElementsByTagName('requestCookie')[0].firstChild.nodeValue
            else:
                xmlData['requestCookie'] = ''
            # set success match if specified in the module XML
            if each.getElementsByTagName('successmatch')[0].firstChild:
                xmlData['successmatch'] = each.getElementsByTagName('successmatch')[0].firstChild.nodeValue
            else:
                xmlData['successmatch'] = ''
            # set negative match if specified in the module XML
            if each.getElementsByTagName('negativematch')[0].firstChild:
                xmlData['negativematch'] = each.getElementsByTagName('negativematch')[0].firstChild.nodeValue
            else:
                xmlData['negativematch'] = ''
            xmlData['date'] = each.getElementsByTagName('date')[0].firstChild.nodeValue
            # set module version if specified in the module XML
            if each.getElementsByTagName('version')[0].firstChild:
                xmlData['version'] = each.getElementsByTagName('version')[0].firstChild.nodeValue
            else:
                xmlData['version'] = ''
            xmlData['author'] = each.getElementsByTagName('author')[0].firstChild.nodeValue
            xmlData['category'] = each.getElementsByTagName('category')[0].firstChild.nodeValue

            # filter modules based on selected categories
            if xmlData['category'].lower() in opts.category.lower() or \
                opts.category.lower() == "all" or \
                (opts.single.lower() and opts.single.lower() in xmlData['name'].lower()):
                if xmlData['category'].lower() == "example" and \
                    "example" not in opts.category.lower():
                    # skip example module when running with all or default settings
                    if opts.verbose:
                        print "\t\t[!] Skipping example module : %s" % xmlData['name']
                else:
                    print "\t\t[ ] Extracted module information from %s" % xmlData['name']
                    modules.append(xmlData)
            else:
                print "\t\t[!] Skipping module %s as it does not match the selected category (%s)" % (xmlData['name'], opts.category)

        except Exception, e:
            print "\t\t[!] Failed to extracted module information\n\t\tError: %s" % e
            if opts.debug:
                print traceback.print_exc(file=sys.stdout)
            continue

def output_modules():
    # print information about the loaded module(s)

    print "\n\t----------------------------------------------------------------------------------------------"
    print string.center(">>>>> Module Information <<<<<", 103)
    print "\t----------------------------------------------------------------------------------------------"
    for mod in modules:
        print textwrap.fill(("\tNAME: %s" % mod['name']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tURL: %s" % mod['url']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tMETHOD: %s" % mod['method']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tHEADERS: %s" % mod['headers']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tPOST PARAMETERS: %s" % mod['postParameters']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tREQUEST COOKIE: %s" % mod['requestCookie']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tSUCCESS MATCH: %s" % mod['successmatch']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tNEGATIVE MATCH: %s" % mod['negativematch']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tDATE: %s" % mod['date']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tVERSION: %s" % mod['version']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tAUTHOR: %s" % mod['author']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tCATEGORY: %s" % mod['category']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print "\t----------------------------------------------------------------------------------------------"

def output_accounts():
    # print information about the accounts loaded from accountfile

    print "\n\t----------------------------------------------------------------------------------------------"
    print string.center(">>>>> Accounts Loaded <<<<<", 103)
    print "\t----------------------------------------------------------------------------------------------"
    for a in accounts:
        print textwrap.fill(("\tAccount name: %s" % a),
            initial_indent='', subsequent_indent='\t\t', width=103)
    print "\t----------------------------------------------------------------------------------------------\n"

def output_success():
    # print information about success matches

    print "\n\t----------------------------------------------------------------------------------------------"
    print string.center(">>>>> Successful matches <<<<<", 103)
    print "\t----------------------------------------------------------------------------------------------"
    for s in success:
        print textwrap.fill(("\tNAME: %s" % s['name']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tACCOUNT: %s" % s['account']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tURL: %s" % s['url']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tMETHOD: %s" % s['method']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\tPOST PARAMETERS: %s" % s['postParameters']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print "\t----------------------------------------------------------------------------------------------"

def load_modules():
    # load the modules from moduledir
    # only XML files are permitted

    for (path, dirs, files) in os.walk(opts.moduledir):
        for d in dirs:
           if d.startswith("."): # ignore hidden . dirctories
               dirs.remove(d)
        print "\t[-] Starting to load modules from %s\n" % path
        for file in files:
            if not path.endswith('/'):
                path = path + '/'
            # read in modules
            if file.endswith('.xml') and not file.startswith('.'):
                print '\t\t[ ] Loading module : %s' % file,
                module_dom = parse(path + file)
                module_dom = module_dom.getElementsByTagName('site')
                extract_module_data(module_dom)
            elif opts.verbose:
                print '\t\t[!] Skipping non XML file : %s' % file

    if opts.verbose:
        output_modules()  #debug output

def load_accounts():
    # load accounts from accountfile
    # one account per line

    account_file = open(opts.accountfile, 'r')
    account_read = account_file.readlines()
    account_read = [item.rstrip() for item in account_read]
    for a in account_read:
        if not a.startswith("#"): # ignore comment lines in accountfile
            accounts.append(a)

    if opts.verbose:
        output_accounts()  # debug output

def create_testcases():
    # create a list of testcases from accounts and modules
    #
    # replace functions are in place to replace <ACCOUNT> with the account names presented
    # the script will also replace any instances of <RANDOM> with a random string (8) to avoid detection

    testcases = []
    tempcase = {}
    for a in accounts:
        for m in modules:
            rand = ''.join( Random().sample(string.letters+string.digits, 8) ) # 8 random chars
            tempcase['url'] = m['url'].replace("<ACCOUNT>", a).replace("<RANDOM>", rand)
            tempcase['account'] = a
            tempcase['name'] = m['name']
            tempcase['method'] = m['method']
            tempcase['postParameters'] = m['postParameters'].replace("<ACCOUNT>", a).replace("<RANDOM>", rand)
            tempcase['headers'] = m['headers']
            tempcase['requestCookie'] = m['requestCookie']
            tempcase['successmatch'] = m['successmatch']
            tempcase['negativematch'] = m['negativematch']
            testcases.append(tempcase)
            tempcase = {}

    return testcases

def make_requests(testcases):
    # make a requests present in testcases

    print "\n\t----------------------------------------------------------------------------------------------"
    print string.center(">>>>> Testcases <<<<<", 103)
    print "\t----------------------------------------------------------------------------------------------"
    print "\t[-] Starting testcases (%d in total)\n" % len(testcases)
    progress = 0 # initiate progress count
    progress_last = 0

    for test in testcases:
        if not progress == 0:
            progress_percentage = int(100 / (float(len(testcases)) / float(progress)))
            if progress_percentage - progress_last > 20: # only update percentage in 20% chunks
                print '\n\t[-] [%s] %s%% complete\n' % (('#'*(progress_percentage / 10)).ljust(10, "."),progress_percentage)
                progress_last = progress_percentage
        if test['method'] == 'GET':
            resp = get_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print "\t----------------------------------------------------------------------------------------------"
                    print '\t[X] success matched %s on %s' % (test['account'], test['name'])
                    print "\t----------------------------------------------------------------------------------------------"
                    success.append(test)
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print '\t[ ] negative matched %s on %s' % (test['account'], test['name'])
        elif test['method'] == 'POST':
            resp = post_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print "\t----------------------------------------------------------------------------------------------"
                    print '\t[X] success matched %s on %s' % (test['account'], test['name'])
                    print "\t----------------------------------------------------------------------------------------------"
                    success.append(test)
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print '\t[ ] negative matched %s on %s' % (test['account'], test['name'])
        else:
            print "\t[!] Unknown Method %s : %s" % test['method'], test['url']

        progress = progress +1 # iterate progress value for the progress bar

def get_request(test):
    # perform GET request

    if opts.verbose:
        print "\t[ ] URL (GET): %s" % test['url']
    try:
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        req_headers = { 'User-Agent' : user_agent }
        for each in test['headers']:
            key, val = each.split(":", 1)
            req_headers[key] = val
        req = urllib2.Request(test['url'], '',req_headers)
        f = urllib2.urlopen(req)
        resp = f.read()
        f.close()
        return resp
    except Exception,e:
        print '\t[!] Error contacting %s' % test['url']
        print '\t[!] Error : %s' % e
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def post_request(test):
    # perform POST request

    if opts.verbose:
        print textwrap.fill(("\t[ ] URL (POST): %s" % test['url']),
            initial_indent='', subsequent_indent='\t\t', width=103)
        print textwrap.fill(("\t\t[ ] POST PARAMETERS: %s" % test['postParameters']),
            initial_indent='', subsequent_indent='\t\t', width=103)
    try:
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        req_headers = { 'User-Agent' : user_agent }
        for each in test['headers']:
            key, val = each.split(":", 1)
            req_headers[key] = val
        if test['requestCookie']:
            cookie_val = request_cookie(test)
            req_headers['cookie'] = cookie_val
        req = urllib2.Request(test['url'], test['postParameters'], req_headers)
        f = urllib2.urlopen(req)
        resp = f.read()
        f.close()

        return resp
    except Exception,e:
        print '\t[!] Error contacting %s' % test['url']
        print '\t[!] Error : %s' % e
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def request_cookie(test):
    # request a cookie from the target site for use during the logon attempt

    user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    req_headers = { 'User-Agent' : user_agent }
    url = test['url'].split("&", 1)[0] # strip parameters from url where present
    req_cookie = urllib2.Request(url, '', req_headers)
    resp_cookie = urllib2.urlopen(req_cookie)
    cookie = resp_cookie.info().getheader('Set-Cookie') # grab cookies

    return cookie

def success_check(data, successmatch):
    # checks response data against successmatch regex

    try:
        regex = re.compile(successmatch)
        if regex.search(data):
            return True
        else:
            return False
    except:
        print '[!] Invalid in success check. Please check the successcheck parameter'
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def negative_check(data, negativematch):
    # checks response data against negativematch regex

    try:
        regex = re.compile(negativematch)
        if regex.search(data):
            return True
        else:
            return False
    except:
        print '[!] Invalid in negative check. Please set the negativecheck parameter'
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def signal_handler(signal, frame):
    # handle CTRL + C events

        if not len(success) == 0:
            print "\n[!] Outputting successful findings and closing\n"
            output_success()
        print '\n\n[!] Ctrl+C detected... exiting\n'
        os._exit(1)

def query_user(question):
    # query user for Y/N response

    valid = {"yes":True, "y":True, "no":False, "n":False}
    prompt = " [y/N] :"

    while True:
        print question + prompt,
        try:
            choice = raw_input().lower()
        except:
            print '\n\n[!] Ctrl+C detected... exiting\n'
            sys.exit(0)
        if choice == '':
            return valid["no"]
        elif choice in valid:
            return valid[choice]
        else:
            print "\t[!] Please respond with 'yes' or 'no'\n"

def setup():
    # setup options

    signal.signal(signal.SIGINT, signal_handler)

    # handle command line options
    global opts
    parser = OptionParser(version="%prog version ::: " + __version__, epilog="\n")
    parser.add_option(
        "-a", "--accountfile",
        dest="accountfile",
        default="./accountfile.txt",
        help="Location of the accounts FILE - 1 account per line",
        metavar="FILE"
        )
    parser.add_option(
        "-m", "--moduledir",
        dest="moduledir",
        default="./modules/",
        help="Location of the modules directory",
        metavar="STRING"
        )
    parser.add_option(
        "-c", "--category",
        dest="category",
        default="all",
        help="Restrict modules based on category (comma seperated)",
        metavar="STRING"
        )
    parser.add_option(
        "-s", "--single",
        dest="single",
        default="",
        help="Restrict to specific module name (name from XML)",
        metavar="STRING"
        )
    parser.add_option(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="Print verbose messages to stdout"
        )
    parser.add_option(
        "-d", "--debug",
        action="store_true",
        dest="debug",
        default=False,
        help=SUPPRESS_HELP
        ) # hidden debug options --> Traceback output for debugging only
    parser.add_option(
        "-?",
        action="store_true",
        dest="question",
        default=False,
        help=SUPPRESS_HELP
        ) # hidden -? handling
    (opts, args) = parser.parse_args()

    if opts.single:
        opts.category = "single" # clear category if single module specified

    if opts.question: # print help on -? also
        parser.print_help()
        sys.exit(0)

    # attempt to handle situations where no module or account file is specified
    if (opts.moduledir == './modules' and opts.accountfile == './accountfile.txt' \
        and len(sys.argv) < 3) or len(sys.argv) < 3:
        print "\t[ ] No command-line options specified"
        user_input = query_user("\t[?] Use default locations and load ALL modules? (dangerous)")
        if user_input:
            # continue using defaults
            print "\t[ ] Continuing using defaults"
        else:
            print "\n",
            parser.print_help()
            parser.exit(0, "\n\t[!] Please specify arguments\n")
    display_options()

def display_options():
    # print out the options being used

    print "\n\t----------------------------------------------------------------------------------------------"
    print textwrap.fill(("\t[ ] Account File :::\t\t%s" % opts.accountfile),
            initial_indent='', subsequent_indent='\t\t', width=103)
    print textwrap.fill(("\t[ ] Module Directory :::\t%s" % opts.moduledir),
            initial_indent='', subsequent_indent='\t\t', width=103)
    if not opts.single:
        print textwrap.fill(("\t[ ] Categories :::\t\t%s" % opts.category),
                initial_indent='', subsequent_indent='\t\t', width=103)
    else:
        print textwrap.fill(("\t[ ] Single :::\t\t\t%s" % opts.single),
                initial_indent='', subsequent_indent='\t\t', width=103)
    print "\t[ ] Verbose :::\t\t\t%s" % opts.verbose
    print "\t----------------------------------------------------------------------------------------------\n"


def main():
    logo()
    setup()
    load_modules()
    load_accounts()
    testcases = create_testcases()
    make_requests(testcases)

    # print success matches
    if len(success) > 0:
        output_success()
    else:
        sys.exit("\n\t[!] No matches found. Exiting!")

main()
