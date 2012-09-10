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

    External module depenancies: colorama (Windows only, optional)

"""

import os
import re
import signal
import urllib2
import string
import textwrap
import sys
import traceback
import time
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
color = {}
startTime = time.clock()

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
    print string.rjust('ver ' + __version__ + ' (' + __codename__ + ')', 74)
    print string.rjust(__maintainer__, 73)

def extract_module_data(module_dom):
    # extract module information from the provided dom

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
                        print "\t[" + color['red'] + "!" + color['end'] + "] Skipping example module : %s" % xmlData['name']
                else:
                    print "\t[-] Extracted module information from %s" % xmlData['name']
                    modules.append(xmlData)
            else:
                if opts.verbose:
                    print "\t[" + color['red'] + "!" + color['end'] + "] Skipping module %s. Not in category (%s)" % (xmlData['name'], opts.category)

        except Exception, e:
            print "\t[" + color['red'] + "!" + color['end'] + "] Failed to extracted module information\n\t\tError: %s" % e
            if opts.debug:
                print traceback.print_exc(file=sys.stdout)
            continue

def output_modules():
    # print information about the loaded module(s)

    print "\n ------------------------------------------------------------------------------"
    print string.center(">>>>> Module Information <<<<<", 80)
    print " ------------------------------------------------------------------------------"
    if opts.verbose and not opts.listmodules:
        for mod in modules:
            print textwrap.fill((" NAME: %s" % mod['name']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" URL: %s" % mod['url']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" METHOD: %s" % mod['method']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" HEADERS: %s" % mod['headers']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" POST PARAMETERS: %s" % mod['postParameters']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" REQUEST COOKIE: %s" % mod['requestCookie']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" SUCCESS MATCH: %s" % mod['successmatch']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" NEGATIVE MATCH: %s" % mod['negativematch']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" DATE: %s" % mod['date']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" VERSION: %s" % mod['version']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" AUTHOR: %s" % mod['author']),
                initial_indent='', subsequent_indent='\t', width=80)
            print textwrap.fill((" CATEGORY: %s" % mod['category']),
                initial_indent='', subsequent_indent='\t', width=80)
            print " ------------------------------------------------------------------------------"
    else:
        print " ", "| Name |".ljust(35), "| Category |".ljust(26), "| Version |".ljust(8)
        print " ------------------------------------------------------------------------------"
        for mod in modules:
            print "  " + mod['name'].ljust(37) + mod['category'].ljust(30) + mod['version'].ljust(10)
        print " ------------------------------------------------------------------------------\n"
        sys.exit(0)

def output_accounts():
    # print information about the accounts loaded from accountfile

    print "\n ------------------------------------------------------------------------------"
    print string.center(">>>>> Accounts Loaded <<<<<", 80)
    print " ------------------------------------------------------------------------------"
    for a in accounts:
        print textwrap.fill((" Account name: %s" % a),
            initial_indent='', subsequent_indent='\t', width=80)
    print " ------------------------------------------------------------------------------\n"

def output_success():
    # print information about success matches

    if opts.summary or opts.verbose:
        print "\n ------------------------------------------------------------------------------"
        print string.center(">>>>> Successful matches <<<<<", 80)
        print " ------------------------------------------------------------------------------"
        print "\n ------------------------------------------------------------------------------"
        print " ", "| Module |".ljust(35), "| Account |".ljust(28)
        print " ------------------------------------------------------------------------------"
        s_success = sorted(success, key=lambda k: k['name']) # group by site name

        if not opts.verbose:
            for s in s_success:
                print "  " + s['name'].ljust(37) + s['account'].ljust(30)
            print " ------------------------------------------------------------------------------\n"
            return
        else:
            for s in s_success:
                print textwrap.fill((" NAME: %s" % s['name']),
                    initial_indent='', subsequent_indent='\t', width=80)
                print textwrap.fill((" ACCOUNT: %s" % s['account']),
                    initial_indent='', subsequent_indent='\t', width=80)
                print textwrap.fill((" URL: %s" % s['url']),
                    initial_indent='', subsequent_indent='\t', width=80)
                print textwrap.fill((" METHOD: %s" % s['method']),
                    initial_indent='', subsequent_indent='\t', width=80)
                print textwrap.fill((" POST PARAMETERS: %s" % s['postParameters']),
                    initial_indent='', subsequent_indent='\t', width=80)
            print " ------------------------------------------------------------------------------"
    else:
        print " ------------------------------------------------------------------------------\n"

def load_modules():
    # load the modules from moduledir
    # only XML files are permitted

    for (path, dirs, files) in os.walk(opts.moduledir):
        for d in dirs:
           if d.startswith("."): # ignore hidden . dirctories
               dirs.remove(d)
        print " [-] Starting to load modules from %s\n" % path
        for file in files:
            if not path.endswith('/'):
                path = path + '/'
            # read in modules
            if file.endswith('.xml') and not file.startswith('.'):
                print "\t[ ] Checking module : %s" % file,
                module_dom = parse(path + file)
                module_dom = module_dom.getElementsByTagName('site')
                extract_module_data(module_dom)
            elif opts.verbose:
                print "\t[" + color['red'] + "!" + color['end'] + "] Skipping non-XML file : %s" % file

    if opts.verbose or opts.listmodules:
        output_modules()  #debug and module output

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

    print "\n ------------------------------------------------------------------------------"
    print string.center(">>>>> Testcases <<<<<", 80)
    print " ------------------------------------------------------------------------------"
    print " [-] Starting testcases (%d in total)\n" % len(testcases)
    progress = 0 # initiate progress count
    progress_last = 0

    for test in testcases:
        if len(testcases) > 50: # only show progress on tests of > 50
            if not progress == 0:
                progress_percentage = int(100 / (float(len(testcases)) / float(progress)))
                if progress_percentage - progress_last > 20: # only update percentage in 20% chunks
                    print " [-] [%s] %s%% complete\n" % ((color['yellow'] + ("#"*(progress_percentage / 10)) + color['end']).ljust(10, "."),progress_percentage),
                    progress_last = progress_percentage
        if test['method'] == 'GET':
            resp = get_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print " [" + color['green'] + "X" + color['end'] + "] Account %s exists on %s" \
                        % (test['account'], test['name'])
                    success.append(test)
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print " [ ] Negative matched %s on %s" % (test['account'], test['name'])
        elif test['method'] == 'POST':
            resp = post_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print " [" + color['green'] + "X" + color['end'] + "] Account %s exists on %s" \
                        % (test['account'], test['name'])
                    success.append(test)
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print " [ ] Negative matched %s on %s" % (test['account'], test['name'])
        else:
            print "[" + color['red'] + "!" + color['end'] + "] Unknown Method %s : %s" % test['method'], test['url']

        progress = progress +1 # iterate progress value for the progress bar

def get_request(test):
    # perform GET request

    if opts.verbose:
        print " [ ] URL (GET): %s" % test['url']
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
        print "\t[" + color['red'] + "!" + color['end'] + "] Error contacting %s" % test['url']
        print "\t[" + color['red'] + "!" + color['end'] + "] Error : %s" % e
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def post_request(test):
    # perform POST request

    if opts.verbose:
        print textwrap.fill((" [ ] URL (POST): %s" % test['url']),
            initial_indent='', subsequent_indent='\t', width=80)
        print textwrap.fill((" [ ] POST PARAMETERS: %s" % test['postParameters']),
            initial_indent='', subsequent_indent='\t', width=80)
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
        print "\t[" + color['red'] + "!" + color['end'] + "] Error contacting %s" % test['url']
        print "\t[" + color['red'] + "!" + color['end'] + "] Error : %s" % e
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
        print "[" + color['red'] + "!" + color['end'] + "] Invalid in success check. Please check parameter"
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
        print "[" + color['red'] + "!" + color['end'] + "] Invalid in negative check. Please check parameter"
        if opts.debug:
            print traceback.print_exc(file=sys.stdout)

def signal_handler(signal, frame):
    # handle CTRL + C events

        if not len(success) == 0:
            print "\n[" + color['red'] + "!" + color['end'] + "] Outputting successful findings and closing\n"
            print "[-] tests stopped after %.2f seconds" % (time.clock() - startTime)
            output_success()
        print "\n\n[" + color['red'] + "!" + color['end'] + "] Ctrl+C detected... exiting\n"
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
            print "\n\n[" + color['red'] + "!" + color['end'] + "] Ctrl+C detected... exiting\n"
            sys.exit(0)
        if choice == '':
            return valid["no"]
        elif choice in valid:
            return valid[choice]
        else:
            print "\t[" + color['red'] + "!" + color['end'] + "] Please respond with 'yes' or 'no'\n"

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
        "-l", "--list",
        action="store_true",
        dest="listmodules",
        default=False,
        help="List modules w/name and category",
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
        "--summary",
        action="store_true",
        dest="summary",
        default=False,
        help="Show detailed summary at the end",
        )
    parser.add_option(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="Print verbose messages to stdout (-d for debug output)"
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

    # set verbose on debug
    if opts.debug:
        opts.verbose = True

    # set ansi colors for supported platforms (!= Windows)
    if sys.platform.startswith("win"):
        try:
            import colorama
            colorama.init()
            color['red'] = colorama.Fore.RED + colorama.Style.BRIGHT
            color['green'] = colorama.Fore.GREEN + colorama.Style.BRIGHT
            color['yellow'] = colorama.Fore.YELLOW + colorama.Style.BRIGHT
            color['end'] = colorama.Fore.RESET + colorama.Style.RESET_ALL
        except:
            print "\t[!] Colorama Python module not found, color support disabled"
            color['red'] = ""
            color['green'] = ""
            color['yellow'] = ""
            color['end'] = ""
    else:
        color['red'] = "\033[1;31m"
        color['green'] = "\033[1;32m"
        color['yellow'] = "\033[1;33m"
        color['end'] = "\033[0m"

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
            parser.exit(0, "\n\t[" + color['red'] + "!" + color['end'] +"] Please specify arguments\n")
    display_options()

def display_options():
    # print out the options being used

    print "\n ------------------------------------------------------------------------------"
    print textwrap.fill(("\t[ ] Account File :::\t\t%s" % opts.accountfile),
            initial_indent='', subsequent_indent='\t\t', width=80)
    print textwrap.fill(("\t[ ] Module Directory :::\t%s" % opts.moduledir),
            initial_indent='', subsequent_indent='\t\t', width=80)
    if not opts.single:
        print textwrap.fill(("\t[ ] Categories :::\t\t%s" % opts.category),
                initial_indent='', subsequent_indent='\t\t', width=80)
    else:
        print textwrap.fill(("\t[ ] Single Module :::\t\t%s" % opts.single),
                initial_indent='', subsequent_indent='\t\t', width=80)
    print "\t[ ] Verbose :::\t\t\t%s" % opts.verbose
    print " ------------------------------------------------------------------------------\n"


def main():
    logo()
    setup()
    load_modules()
    load_accounts()
    testcases = create_testcases()
    make_requests(testcases)

    # print success matches
    print "\n [-] tests completed in %.2f seconds" % (time.clock() - startTime)
    if len(success) > 0:
        output_success()
    else:
        sys.exit("\n\t[" + color['red'] + "!" + color['end'] + "] No matches found. Exiting!")

main()
