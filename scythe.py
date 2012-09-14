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

    External module depenancies: 
        colorama (Windows only, optional)

"""

import os
import re
import signal
import urllib
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
__version__ = '0.1.5'
__codename__ = 'Lazy Lizard'
__date__ = '13 September 2012'
__maintainer__ = 'ChrisJohnRiley'
__email__ = 'contact@c22.cc'
__status__ = 'Beta'

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

def extract_module_data(file, module_dom):
    # extract module information from the provided dom

    print "\n",
    for each in module_dom:
        try:
            xmlData = {}

            # try/except blocks to handle badly formed XML modules
            try:
                xmlData['name'] = each.getElementsByTagName('name')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['name'] = 'unspecified'

            # set URL - prepend http:// if not present in string
            if not each.getElementsByTagName('url')[0].firstChild.nodeValue.startswith('http'):
                xmlData['url'] = 'http://' + each.getElementsByTagName('url')[0].firstChild.nodeValue
            else:
                xmlData['url'] = each.getElementsByTagName('url')[0].firstChild.nodeValue

            # set Method
            try:
                xmlData['method'] = each.getElementsByTagName('method')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                # default to GET if not specified
                xmlData['method'] = 'GET'

            # set POST Parameters if set in the module XML
            try:
                if each.getElementsByTagName('postParameters')[0].firstChild.nodeValue.lower() == 'false':
                    # handle instances where people enter False insterad of leaving this field blank
                    xmlData['postParameters'] = ''
                else:
                    xmlData['postParameters'] = \
                        each.getElementsByTagName('postParameters')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['postParameters'] = ''

            # set headers if set in the module XML
            try:
                if each.getElementsByTagName('headers')[0].firstChild.nodeValue.lower() == 'false':
                    # handle instances where people enter False insterad of leaving this field blank
                    xmlData['headers'] = ''
                else:
                    xmlData['headers'] = \
                        each.getElementsByTagName('headers')[0].firstChild.nodeValue.split(",")
            except (IndexError, AttributeError):
                xmlData['headers'] = ''

            # set request cookie if set in the module XML
            try:
                if each.getElementsByTagName('requestCookie')[0].firstChild.nodeValue.lower() == 'true':
                    xmlData['requestCookie'] = True
                else:
                    xmlData['requestCookie'] = False
            except (IndexError, AttributeError):
                xmlData['requestCookie'] = False

            # set csrf mode if set in the module XML
            try:
                if each.getElementsByTagName('requestCSRF')[0].firstChild.nodeValue.lower() == 'false':
                    xmlData['requestCSRF'] = False
                else:
                    xmlData['requestCSRF'] = \
                        each.getElementsByTagName('requestCSRF')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['requestCSRF'] = False

            # set success match if specified in the module XML
            try:
                xmlData['successmatch'] = \
                    each.getElementsByTagName('successmatch')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['successmatch'] = ''

            # set negative match if specified in the module XML
            try:
                # handle instances where people enter False insterad of leaving this field blank
                if each.getElementsByTagName('negativematch')[0].lower() == 'false':
                    xmlData['negativematch'] = ''
                else:
                    xmlData['negativematch'] = \
                        each.getElementsByTagName('negativematch')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['negativematch'] = ''

            # set module date
            try:
                xmlData['date'] = each.getElementsByTagName('date')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['date'] =  'unspecified'

            # set module version if specified in the module XML
            try:
                xmlData['version'] = each.getElementsByTagName('version')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['version'] = 'unspecified'

            # set module author
            try:
                xmlData['author'] = each.getElementsByTagName('author')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['author'] = 'unlisted'

            # set category
            try:
                xmlData['category'] = each.getElementsByTagName('category')[0].firstChild.nodeValue
            except (IndexError, AttributeError):
                xmlData['category'] = 'unspecified'

            # filter modules based on selected categories
            if xmlData['category'].lower() in opts.category.lower() or \
                opts.category.lower() == "all" or \
                (opts.single.lower() and opts.single.lower() in xmlData['name'].lower()) or \
                (file.lower() in opts.single.lower()):
                if xmlData['category'].lower() == "example" and \
                    "example" not in opts.category.lower():
                    # skip example module when running with all or default settings
                    if opts.verbose:
                        print "\t[" + color['red'] + "!" + color['end'] \
                            + "] Skipping example module : %s" % xmlData['name']
                else:
                    print "\t[" + color['yellow'] + "-" + color['end'] \
                        +"] Extracted module information from %s" % xmlData['name']
                    modules.append(xmlData)
            else:
                if opts.verbose:
                    print "\t[" + color['red'] + "!" + color['end'] \
                        + "] Skipping module %s. Not in category (%s)" \
                        % (xmlData['name'], opts.category)

        except Exception, e:
            print "\t[" + color['red'] + "!" + color['end'] \
                + "] Failed to extracted module information\n\t\tError: %s" % e
            if opts.debug:
                print "\n\t[" + color['red'] + "!" + color['end'] + "] ",
                traceback.print_exc()
            continue

def output_modules():
    # print information about the loaded module(s)

    print "\n ------------------------------------------------------------------------------"
    print string.center(">>>>> Module Information <<<<<", 80)
    print " ------------------------------------------------------------------------------"
    if opts.verbose and not opts.listmodules:
        for mod in modules:
            print textwrap.fill((" NAME: %s" % mod['name']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" URL: %s" % mod['url']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" METHOD: %s" % mod['method']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" HEADERS: %s" % mod['headers']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" POST PARAMETERS: %s" % mod['postParameters']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" REQUEST COOKIE: %s" % mod['requestCookie']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" REQUEST CSRF TOKEN: %s" % mod['requestCSRF']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" SUCCESS MATCH: %s" % mod['successmatch']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" NEGATIVE MATCH: %s" % mod['negativematch']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" DATE: %s" % mod['date']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" VERSION: %s" % mod['version']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" AUTHOR: %s" % mod['author']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" CATEGORY: %s" % mod['category']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print " ------------------------------------------------------------------------------"
    else:
        print " ", "| Name |".ljust(35), "| Category |".ljust(26), "| Version |".ljust(8)
        print " ------------------------------------------------------------------------------"
        for mod in modules:
            print "  " + mod['name'].ljust(37) + mod['category'].ljust(30) + mod['version'].ljust(10)
        print " ------------------------------------------------------------------------------\n"
        # exit after providing module list
        sys.exit(0)

def output_accounts():
    # print information about the accounts loaded from accountfile

    print "\n ------------------------------------------------------------------------------"
    print string.center(">>>>> Accounts Loaded <<<<<", 80)
    print " ------------------------------------------------------------------------------"
    for a in accounts:
        print textwrap.fill((" Account name: %s" % a),
            initial_indent='', subsequent_indent=' -> ', width=80)
    print " ------------------------------------------------------------------------------\n"

def output_success():
    # print information about success matches

    if opts.summary or opts.verbose:
        print "\n ------------------------------------------------------------------------------"
        print string.center(">>>>> Successful matches <<<<<", 80)
        print " ------------------------------------------------------------------------------"
        s_success = sorted(success, key=lambda k: k['name']) # group by site name
        # print normal summary table on request (--summary)
        if not opts.verbose and opts.summary:
            print "\n ------------------------------------------------------------------------------"
            print " ", "| Module |".ljust(35), "| Account |".ljust(28)
            print " ------------------------------------------------------------------------------"
            for s in s_success:
                print "  " + s['name'].ljust(37) + s['account'].ljust(30)
            print " ------------------------------------------------------------------------------\n"
        # print verbose summary on request (-v --summary)
        elif opts.verbose and opts.summary:
            for s in s_success:
                print textwrap.fill((" NAME: \t\t\t%s" % s['name']),
                    initial_indent='', subsequent_indent='\t -> ', width=80)
                print textwrap.fill((" ACCOUNT: \t\t%s" % s['account']),
                    initial_indent='', subsequent_indent='\t -> ', width=80)
                print textwrap.fill((" URL: \t\t\t%s" % s['url']),
                    initial_indent='', subsequent_indent='\t -> ', width=80)
                print textwrap.fill((" METHOD: \t\t%s" % s['method']),
                    initial_indent='', subsequent_indent='\t -> ', width=80)
                print textwrap.fill((" POST PARAMETERS: \t%s" % s['postParameters']),
                    initial_indent='', subsequent_indent='\t -> ', width=80)
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
        print " [" + color['yellow'] + "-" + color['end'] \
            +"] Starting to load modules from %s\n" % path
        for file in files:
            if not path.endswith('/'):
                path = path + '/'
            # read in modules
            if file.endswith('.xml') and not file.startswith('.'):
                print "\t[ ] Checking module : %s" % file,
                module_dom = parse(path + file)
                module_dom = module_dom.getElementsByTagName('site')
                extract_module_data(file, module_dom)
            elif opts.verbose:
                print "\t[" + color['red'] + "!" + color['end'] \
                    + "] Skipping non-XML file : %s" % file

    if opts.verbose or opts.listmodules:
        output_modules()  #debug and module output

def load_accounts():
    # if account is passed in we use that, otherwise
    # load accounts from accountfile
    # one account per line

    if opts.account:
    # load account from command line
        if opts.verbose:
            print " [" + color['yellow'] + "-" + color['end'] \
                + "] using command line supplied user : %s" % opts.account
        accounts.append(opts.account)

    else:
    # load accounts from file
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
    # replace functions are in place to replace <ACCOUNT>
    #  with the account names presented
    # the script will also replace any instances of <RANDOM>
    #  with a random string (8) to avoid detection

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
            tempcase['requestCSRF'] = m['requestCSRF']
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
    print " [" + color['yellow'] + "-" + color['end'] \
        +"] Starting testcases (%d in total)\n" % len(testcases)
    progress = 0 # initiate progress count
    progress_last = 0

    for test in testcases:
        # progressbar
        if len(testcases) > 50: # only show progress on tests of > 50
            if not progress == 0:
                progress_percentage = int(100 / (float(len(testcases)) / float(progress)))
                if progress_percentage - progress_last > 20: # only update percentage in 20% chunks
                    print " [" + color['yellow'] + "-" + color['end'] +"] [%s] %s%% complete\n" \
                        % ((color['yellow'] + ("#"*(progress_percentage / 10)) + \
                        color['end']).ljust(10, "."),progress_percentage),
                    progress_last = progress_percentage

        # GET method worker
        if test['method'] == 'GET':
            test, resp = get_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print " [" + color['green'] + "X" + color['end'] + "] Account %s exists on %s" \
                        % (test['account'], test['name'])
                    success.append(test)
                    if opts.outputfile:
                        # log to outputfile
                        opts.outputfile.write("Account " + test['account'] + " exists on " \
                            + test['name'] +"\n")
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print " [" + color['red'] + "X" + color['end'] + "] Negative matched %s on %s" \
                        % (test['account'], test['name'])

        # POST method worker
        elif test['method'] == 'POST':
            test, resp = post_request(test)
            if resp and test['successmatch']:
                matched = success_check(resp, test['successmatch'])
                if matched:
                    print " [" + color['green'] + "X" + color['end'] + "] Account %s exists on %s" \
                        % (test['account'], test['name'])
                    success.append(test)
                    if opts.outputfile:
                        # log to outputfile
                        opts.outputfile.write("Account " + test['account'] + " exists on " \
                            + test['name'] +"\n")
            if resp and test['negativematch']:
                matched = negative_check(resp, test['negativematch'])
                if matched and opts.verbose:
                    print " [" + color['red'] + "X" + color['end'] + "] Negative matched %s on %s" \
                        % (test['account'], test['name'])
        else:
            print "[" + color['red'] + "!" + color['end'] + "] Unknown Method %s : %s" \
                % test['method'], test['url']

        progress = progress +1 # iterate progress value for the progress bar

def get_request(test):
    # perform GET request

    urllib.urlcleanup() # clear cache

    try:
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        req_headers = { 'User-Agent' : user_agent }
        for each in test['headers']:
            key, val = each.split(":", 1)
            req_headers[key] = val
        if test['requestCookie'] or test['requestCSRF']:
            # request cookie and csrf token if set in module XML
            cookie_val, csrf_val = request_value(test)
            if cookie_val:
                req_headers['cookie'] = cookie_val
            if csrf_val:
                # replace <CSRFTOKEN> with the collected token
                test['url'] = test['url'].replace("<CSRFTOKEN>", csrf_val)
                test['postParameters'] = test['postParameters'].replace("<CSRFTOKEN>", csrf_val)

        if opts.debug:
            # print debug output
            print textwrap.fill((" [ ] URL (GET): %s" % test['url']),
                initial_indent='', subsequent_indent=' -> ', width=80)

        req = urllib2.Request(test['url'], '',req_headers)
        f = urllib2.urlopen(req)
        resp = f.read()
        f.close()

        # returned updated test and response data
        return test, resp

    except Exception:
        print textwrap.fill((" [" + color['red'] + "!" + color['end'] + "] Error contacting %s" \
            % test['url']), initial_indent='', subsequent_indent='\t', width=80)
        if opts.debug:
            for ex in traceback.format_exc().splitlines():
                print textwrap.fill((" %s" \
                    % str(ex)), initial_indent='', subsequent_indent='\t', width=80)
            print "\n"
        return test, False

def post_request(test):
    # perform POST request

    urllib.urlcleanup() # clear cache

    try:
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        req_headers = { 'User-Agent' : user_agent }
        if test['headers']:
            for each in test['headers']:
                key, val = each.split(":", 1)
                req_headers[key] = val
        if test['requestCookie'] or test['requestCSRF']:
            # request cookie and csrf token if set in module XML
            cookie_val, csrf_val = request_value(test)
            if cookie_val:
                req_headers['cookie'] = cookie_val
            if csrf_val:
                # replace <CSRFTOKEN> with the collected token
                test['url'] = test['url'].replace("<CSRFTOKEN>", csrf_val)
                test['postParameters'] = test['postParameters'].replace("<CSRFTOKEN>", csrf_val)

        if opts.debug:
            # print debug output
            print textwrap.fill((" [ ] URL (POST): %s" % test['url']),
                initial_indent='', subsequent_indent=' -> ', width=80)
            print textwrap.fill((" [ ] POST PARAMETERS: %s" % test['postParameters']),
                initial_indent='', subsequent_indent=' -> ', width=80)

        req = urllib2.Request(test['url'], test['postParameters'], req_headers)
        f = urllib2.urlopen(req)
        resp = f.read()
        f.close()

        # returned updated test and response data
        return test, resp

    except Exception:
        print textwrap.fill((" [" + color['red'] + "!" + color['end'] + "] Error contacting %s" \
            % test['url']), initial_indent='', subsequent_indent='\t', width=80)
        if opts.debug:
            for ex in traceback.format_exc().splitlines():
                print textwrap.fill((" %s" \
                    % str(ex)), initial_indent='', subsequent_indent='\t', width=80)
            print "\n"
        return test, False

def request_value(test):
    # request a cookie or CSRF token from the target site for use during the logon attempt

    urllib.urlcleanup() # clear cache
    user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    req_headers = { 'User-Agent' : user_agent }
    url = test['url'].split("?", 1)[0] # strip parameters from url where present
    req_val = urllib2.Request(url, '', req_headers)
    response = urllib2.urlopen(req_val)

    # capture Set-Cookie
    if test['requestCookie']:
        if response.info().getheader('Set-Cookie'):
            cookie_val = response.info().getheader('Set-Cookie') # grab cookies
        else:
            cookie_val = False
            print "[" + color['red'] + "!" + color['end'] \
                + "] Set-Cookie Error: No valid Set-Cookie response received"
    else:
        cookie_val = False

    # capture CSRF token (using regex from module XML)
    if test['requestCSRF']:
        try:
            csrf_regex = re.compile(test['requestCSRF'])
            match = re.search(csrf_regex, response.read())
            if match:
                csrf_val = match.group(1)
            else:
                csrf_val = False
                print "[" + color['red'] + "!" + color['end'] \
                    + "] Invalid CSRF regex. Please check parameters"
        except:
            print "[" + color['red'] + "!" + color['end'] \
                + "] Invalid CSRF regex. Please check parameters"
        if opts.debug:
                print "\n\t[" + color['red'] + "!" + color['end'] + "] ",
                traceback.print_exc()
    else:
        csrf_val = False

    return cookie_val, csrf_val

def success_check(data, successmatch):
    # checks response data against successmatch regex

    try:
        regex = re.compile(successmatch)
        if regex.search(data):
            return True
        else:
            return False
    except:
        print "[" + color['red'] + "!" + color['end'] \
            + "] Invalid in success check. Please check parameter"
        if opts.debug:
            print "\n\t[" + color['red'] + "!" + color['end'] + "] ",
            traceback.print_exc()

def negative_check(data, negativematch):
    # checks response data against negativematch regex

    try:
        regex = re.compile(negativematch)
        if regex.search(data):
            return True
        else:
            return False
    except:
        print "[" + color['red'] + "!" + color['end'] \
            + "] Invalid in negative check. Please check parameter"
        if opts.debug:
            print "\n\t[" + color['red'] + "!" + color['end'] + "] ",
            traceback.print_exc()

def signal_handler(signal, frame):
    # handle CTRL + C events

        if not len(success) == 0:
            print "\n[" + color['red'] + "!" + color['end'] \
                + "] Outputting successful findings and closing\n"
            print "[" + color['yellow'] + "-" + color['end'] \
                +"] tests stopped after %.2f seconds" % (time.clock() - startTime)
            output_success()
        print "\n\n [" + color['red'] + "!" + color['end'] + "] Ctrl+C detected... exiting\n"
        if opts.outputfile:
            opts.outputfile.close()
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
            print "\n\n [" + color['red'] + "!" + color['end'] \
                + "] Ctrl+C detected... exiting\n"
            sys.exit(0)
        if choice == '':
            return valid["no"]
        elif choice in valid:
            return valid[choice]
        else:
            print "\t[" + color['red'] + "!" + color['end'] \
                + "] Please respond with 'yes' or 'no'\n"

def setup():
    # setup command line options and handle ctrl+c events

    signal.signal(signal.SIGINT, signal_handler)

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
        "-u", "--account",
        dest="account",
        default="",
        help="Specify a single account on the command line",
        metavar="STRING"
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
        help="List module names and categories",
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
        "-o", "--output",
        dest="outputfile",
        default=False,
        help="Output results to a file as well as screen",
        metavar="FILE"
        )
    parser.add_option(
        "-v", "--verbose",
        action="count",
        dest="verbose",
        help="Print verbose messages to stdout (-v -v for debug output)"
        )
    parser.add_option(
        "-?",
        action="store_true",
        dest="question",
        default=False,
        help=SUPPRESS_HELP
        ) # hidden -? handling
    (opts, args) = parser.parse_args()

    # handle help output

    if opts.question: # print help on -? also
        parser.print_help()
        sys.exit(0)

    # set verbosity level (-v verbose, -v -v verbose and debug)
    if not opts.verbose:
        opts.verbose = False
        opts.debug = False
    elif opts.verbose == 1:
        opts.verbose = True
        opts.debug = False
    else:
        opts.verbose = True
        opts.debug = True

    # set ansi colors for supported platforms (colorama support for Windows)
    if sys.platform.startswith("win"):
        try:
            import colorama
            colorama.init()
            color['red'] = colorama.Fore.RED + colorama.Style.BRIGHT
            color['green'] = colorama.Fore.GREEN + colorama.Style.BRIGHT
            color['yellow'] = colorama.Fore.YELLOW + colorama.Style.BRIGHT
            color['end'] = colorama.Fore.RESET + colorama.Style.RESET_ALL
        except:
            # disable colors on systems without colorama installed
            print "\n\t[!] Colorama Python module not found, color support disabled"
            color['red'] = ""
            color['green'] = ""
            color['yellow'] = ""
            color['end'] = ""
    else:
        # set colors for non-Windows systems
        color['red'] = "\033[1;31m"
        color['green'] = "\033[1;32m"
        color['yellow'] = "\033[1;33m"
        color['end'] = "\033[0m"

    # attempt to handle situations where no module or account file is specified
    # skip section if module output is selected
    if (opts.moduledir == './modules' and opts.accountfile == './accountfile.txt' \
        and not opts.listmodules and len(sys.argv) < 3) or \
        (not opts.listmodules and len(sys.argv) < 3) or \
        (opts.account and len(sys.argv) < 3):
        print "\t[ ] No command-line options specified"
        user_input = query_user("\t[" + color['yellow'] + "?" + color['end'] \
            +"] Use default locations and load ALL modules? (dangerous)")
        if user_input:
            # continue using defaults
            print "\t[ ] Continuing using defaults"
        else:
            print "\n",
            parser.print_help()
            parser.exit(0, "\n\t[" + color['red'] + "!" + color['end'] \
                +"] Please specify arguments\n")
    display_options()

    # check if outputfile exists already and prompt to overwrite
    if opts.outputfile:
        if os.path.exists(opts.outputfile):
            # query user to overwrite existing outputfile
            user_input = query_user("\t[" + color['yellow'] + "?" + color['end'] \
                +"] Overwrite existing outputfile?")
            if user_input:
                print "\t[ ] Overwriting output file : %s\n" % opts.outputfile
            else:
                sys.exit("\n\t[" + color['red'] + "!" + color['end'] \
                +"] Please specify new output file\n")
        # open output file
        try:
            opts.outputfile = open(opts.outputfile, "w")
        except:
            print "[" + color['red'] + "!" + color['end'] \
                + "] Unable to open output file for writing"
            if opts.debug:
                print "\n\t[" + color['red'] + "!" + color['end'] + "] ",
                traceback.print_exc()

    # clear category if single module specified
    if opts.single:
        opts.category = "single"

def display_options():
    # print out the options being used

    print "\n ------------------------------------------------------------------------------"
    if not opts.account:
        print "\t[" + color['yellow'] + "-" + color['end'] +"] Account File :::".ljust(30), \
            str(opts.accountfile).ljust(40)
    else:
        print "\t[" + color['yellow'] + "-" + color['end'] +"] Single Account :::".ljust(30), \
            str(opts.account).ljust(40)
    print "\t[" + color['yellow'] + "-" + color['end'] +"] Module Directory :::".ljust(30), \
        str(opts.moduledir).ljust(40)
    if not opts.single:
        print "\t[" + color['yellow'] + "-" + color['end'] +"] Categories :::".ljust(30), \
            str(opts.category).ljust(40)
    else:
        print "\t[" + color['yellow'] + "-" + color['end'] +"] Single Module :::".ljust(30), \
        str(opts.single).ljust(40)
    print "\t[" + color['yellow'] + "-" + color['end'] +"] Verbose :::".ljust(30), \
        str(opts.verbose).ljust(40)
    if opts.outputfile:
        # get filename based on current path
        file = os.path.realpath(opts.outputfile).replace(os.getcwd(), "")
        print "\t[" + color['yellow'] + "-" + color['end'] +"] Output :::".ljust(30), \
            str(file).ljust(40)
    print " ------------------------------------------------------------------------------\n"


def main():
    logo()
    setup()
    load_modules()
    load_accounts()
    testcases = create_testcases()
    make_requests(testcases)

    # print success matches
    print "\n [" + color['yellow'] + "-" + color['end'] \
        +"] tests completed in %.2f seconds" \
        % (time.clock() - startTime)
    if len(success) > 0:
        output_success()
    else:
        sys.exit("\n\t[" + color['red'] + "!" + color['end'] \
            + "] No matches found. Exiting!")

main()
