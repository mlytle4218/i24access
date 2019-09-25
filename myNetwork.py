#!/usr/bin/env python3

from requests_html import HTMLSession
import random
import json
from pprint import pprint
import time
from urllib.parse import quote, unquote
import re
import brotli
import click
import sys
import subprocess

VERBOSE = 4
INFO = 3
DEBUG = 2
ERROR = 1

log_level = ERROR

# whitespace at line break is relevant
USER_AGENT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) '
              'Chrome/70.0.3538.102 Safari/537.36')
MPV = 'mpv'  # if needed can be changed to an absolute path


def error(msg, exit_code=None):
    print(msg)
    sys.stdout.flush()
    if exit is not None:
        sys.exit(exit_code)


def info(msg, dot_if_suppressed=False):
    if log_level >= INFO:
        print(msg)
        sys.stdout.flush()
    elif dot_if_suppressed:
        sys.stdout.write('.')
        sys.stdout.flush()


def verbose(msg):
    if log_level >= VERBOSE:
        print(msg)
        sys.stdout.flush()


class MyNetwork:
    def __init__(self, session):
        self.session = session

    @staticmethod
    def print_divider():
        verbose('-' * 25)
        verbose('-' * 25)

    @staticmethod
    def get_text_content(req):
        if req.headers.get('content-encoding') == 'br':
            return brotli.decompress(req.content).decode('utf-8')
        else:
            return req.text

    def get(self, url, headers, render=True):
        self.print_divider()
        verbose('GET {}'.format(url))
        r = self.session.get(url, headers=headers)
        # print('Request headers = {}'.format(r.request.headers))
        if render:
            r.html.render()
        verbose('STATUS {}'.format(r.status_code))
        # pprint(r.headers)
        # print(MyNetwork.get_text_content(r))
        # print(r.cookies)
        return r

    def post(self, url, data, headers, render=True):
        h = dict({'content-type': 'application/x-www-form-urlencoded'}, **headers)
        self.print_divider()
        verbose('POST {}'.format(url))

        if log_level >= VERBOSE:
            pprint(h)

        r = self.session.post(url, data=data, headers=h)
        # print('Request headers = {}'.format(r.history[0].request.headers))
        verbose('Request content = {}'.format(r.history[0].request.body))
        if render:
            r.html.render()
        verbose('STATUS {}'.format(r.status_code))
        # pprint(r.headers)
        # print(MyNetwork.get_text_content(r))
        # print(r.cookies)
        return r


class NewsStreamer:
    i24news_headers = {
        'authority': 'video.i24news.tv',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',
        'upgrade-insecure-requests': '1',
        'user-agent': USER_AGENT,
        'dnt': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9'
    }

    cleeng_headers = {
        'authority': 'cleeng.com',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',
        'origin': 'https://cleeng.com',
        'upgrade-insecure-requests': '1',
        'dnt': '1',
        'user-agent': USER_AGENT,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9'
    }

    def __init__(self, session, credentials_filename):
        self.session = session
        self.network = MyNetwork(session)
        self.i24news_accept_json_headers = self.i24news_headers.copy()
        self.i24news_accept_json_headers['accept'] = 'application/json'
        self.uuid = None  # to be collected during authentication
        self._load_credentials(credentials_filename)

    def _load_credentials(self, filename):
        with open(filename) as f:
            self.creds = json.load(f)

    def auth(self):
        if not self.creds:
            error("Credentials for login are required.", exit_code=1)

        # Get main page to set i24news cookies
        info("Load main i24news page", dot_if_suppressed=True)
        self.network.get('https://video.i24news.tv/', self.i24news_headers)

        # Usually user action required to request login
        time.sleep(2)

        # Initial request sets cleeng.com cookies
        info("Call cleeng autologin", dot_if_suppressed=True)
        url = 'https://cleeng.com/autologin/autologin.js?callback=__cleeng_autologin_callback&r={}'.format(
            random.random())
        self.network.get(url, self.cleeng_headers, render=False)

        # Request the login page
        # GET 'https://cleeng.com/auth/2/purchase/?v=3.0&appId={APP_ID}&offerId=S920352949,S920352949_XX&popup=1&redirectUri=https%3A%2F%2Fcleeng.com%2Fjs-api%2F3.0%2Fdefault-channel.html&locale=en_EN&_ga={GA_ID}&'
        # alternatively
        # GET 'https://cleeng.com/auth/2/purchase/?v=3.0&appId={APP_ID}&offerId=S920352949&checkoutType=overlay&redirectUri=https://cleeng.com/js-api/3.0/checkout-channel.html&locale=en_EN'
        info("Request cleeng login page", dot_if_suppressed=True)
        url = ('https://cleeng.com/auth/2/purchase/?v=3.0&appId=35e97a6231236gb456heg6bd7a6bdsf7&offerId=S920352949'
               '&popup=1&redirectUri=https%3A%2F%2Fcleeng.com%2Fjs-api%2F3.0%2Fdefault-channel.html&locale=en_EN').format(
            random.random())
        r = self.network.get(url, self.cleeng_headers, render=False)
        # get the login url with afid and session id:
        login_url = re.compile('action="([^"]*login[^"]*)"').search(MyNetwork.get_text_content(r)).group(1)
        verbose("Extract login url.  login_url={}".format(login_url))

        if 'cleeng.com' not in login_url:
            error('Login URL does not appear to be correct.  Is login url correct?  Please inspect. Aborting.',
                  exit_code=1)

        # Usually user action required to enter credentials
        time.sleep(2)

        # POST request login with credentials form
        # Use login url from previous page load because it has params set
        # Should 302 redirect to login form
        info("Send credentials to cleeng", dot_if_suppressed=True)
        data = 'login%5Bemail%5D={}&authType=1&login%5Bpassword%5D={}&login%5Bsubmit%5D=Login'.format(
            quote(self.creds['username']), quote(self.creds['password']))
        r = self.network.post(login_url, data, self.cleeng_headers, render=False)

        # extract finish URL from page form.  This is a simply a URL path without a domain.
        # Expect the path to be absolute.  Notice starting /.
        finish_url = re.compile('action="(/[^"]*)"').search(MyNetwork.get_text_content(r)).group(1)
        verbose('Extract login completion url.  finish_url={}'.format(finish_url))

        if len(finish_url) < 10:
            error('Is finish_url correct? Aborting', exit_code=1)

        # Usually user action required to press completion button
        time.sleep(2)

        info("Submit login completion request", dot_if_suppressed=True)
        data = 'submit='
        r = self.network.post('https://cleeng.com{}'.format(finish_url), data, self.cleeng_headers, render=False)

        info('Autologin request to cleeng to get key', dot_if_suppressed=True)
        # Get response payload key for next call
        # Response contains javascript callback __cleeng_autologin_callback with JSON object with keys:
        # "available": bool, "name": str, "id": str, "key": str, "accountType": str and "wasLoggedIn": int.
        url = 'https://cleeng.com/autologin/autologin.js?callback=__cleeng_autologin_callback&r={}'.format(
            random.random())
        r = self.network.get(url, self.cleeng_headers, render=False)
        cleeng_key = re.compile('"key":"([a-zA-Z0-9]*)"').search(MyNetwork.get_text_content(r)).group(1)

        verbose('cleeng_key={}'.format(cleeng_key))

        info('Request customerToken', dot_if_suppressed=True)
        # Use key to request customerToken
        params = {"applicationId": "35e97a6231236gb456heg6bd7a6bdsf7", "key": cleeng_key}
        url = 'https://cleeng.com/api/3.0/jsonp?callback=__cleeng_cb_{}&method=autologin&r={}&params={}'.format(
            random.randint(100000, 999999), random.random(), quote(json.dumps(params)))
        r = self.network.get(url, self.cleeng_headers, render=False)
        customerToken = re.compile('"customerToken":"([^"]*)"').search(MyNetwork.get_text_content(r)).group(1)
        verbose('customerToken={}'.format(customerToken))

        info('Set customerToken cookie for i24news', dot_if_suppressed=True)
        # Needs to set cookie CleengClientAccessToken for i24news.tv domain
        self.session.cookies.set('CleengClientAccessToken', customerToken, domain='i24news.tv')

        # also need to set token in i24news headers
        self.i24news_headers['token'] = customerToken
        self.i24news_accept_json_headers['token'] = customerToken

        # Might not be necessary, just returns customer account info, but does show that our customerToken is working.
        # Use customerToken to request video stream.  Params object is URL encoded and passed as query parameter.
        params = {"customerToken": customerToken}

        info('Request cleeng account information', dot_if_suppressed=True)
        url = 'https://cleeng.com/api/3.0/jsonp?callback=__cleeng_cb_{}&method=getCustomer&r={}&params={}'.format(
            random.randint(100000, 999999), random.random(), quote(json.dumps(params)))
        r = self.network.get(url, self.cleeng_headers, render=False)

        info('Request i24news account information to get UUID', dot_if_suppressed=True)
        # get user from i24news.tv
        url = 'https://video.i24news.tv/proxy/account/user?appId=5a8452d11de1c4000c77c692'
        r = self.network.get(url, self.i24news_headers, render=False)

        # uuid is a json field in the user cookie
        # format of unquoted cookie: 'j:{"clientIp":ip-addr-str,"uuid":guid-str}'
        user = self.session.cookies.get('user')
        user_value = unquote(user)
        self.uuid = re.compile('"uuid":"([^"]*)"').search(user_value).group(1)
        verbose('Using uuid=' + self.uuid)

        info('Request i24news for active subscription', dot_if_suppressed=True)
        # switch accept header to only application/json otherwise subscription check returns protobuf
        url = 'https://video.i24news.tv/proxy/account/hasActiveSubscription/?appId=5a8452d11de1c4000c77c692&uuid={}'.format(
            self.uuid)
        r = self.network.get(url, self.i24news_accept_json_headers, render=False)

        if MyNetwork.get_text_content(r) == '{"result":true}':
            info('User has active i24news subscription.', dot_if_suppressed=True)
        else:
            print("")
            error('i24news.tv appears to think there is not an active user subscription.')

        # no longer need token in header
        self.i24news_headers.pop('token', None)
        self.i24news_accept_json_headers.pop('token', None)

        # end with a newline to console so if dots were printed we continue output from a fresh line
        print("")
        sys.stdout.flush()

    def show_menu(self):
        def get_policy_key():
            url = 'https://players.brightcove.net/5377161796001/default_default/index.min.js'
            headers = {
                'user-agent': USER_AGENT,
                'dnt': '1',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9'
            }
            r = self.network.get(url, headers, render=False)
            content = MyNetwork.get_text_content(r)
            return re.search('policyKey: *"([^"]*)"', content).group(1)

        def get_brightcove(assetId, policy_key):
            url = 'https://edge.api.brightcove.com/playback/v1/accounts/5377161796001/videos/' + assetId
            # Note specially formed accept header that includes policy key
            headers = {
                'accept': 'application/json;pk={}'.format(policy_key),
                'origin': 'https://video/i24news.tv',
                'user-agent': USER_AGENT,
            }
            r = self.network.get(url, headers, render=False)

            # Need to extract the akamaized src -- there may be multiple src to sort through.
            # returns a json document
            return json.loads(MyNetwork.get_text_content(r))

        def stream_media(brightcove_descriptor):
            # pprint(brightcove_descriptor)

            sources = brightcove_descriptor['sources']
            while True:
                for ii, s in enumerate(sources):
                    title = s['type']
                    if 'ext_x_version' in s:
                        title += ' (version {})'.format(s['ext_x_version'])
                    if s['src'].startswith('http://'):
                        title += ' [http]'
                    elif s['src'].startswith('https://'):
                        title += ' [https]'
                    print("{}. {}".format(ii, title))

                selection = input('Attempt to stream which? (x = exit) ')
                try:
                    selection = int(selection)
                    if (selection in range(len(sources))):
                        url = sources[selection]['src']
                        info('Playing with {}'.format(MPV))
                        subprocess.run([MPV, '--no-video', url])
                        break
                except ValueError:
                    if selection == 'x':
                        break

        def save_media_sources(brightcove_descriptor):
            headers = {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'origin': 'https://video/i24news.tv',
                    'user-agent': USER_AGENT
                    }
            for ii, s in enumerate(brightcove_descriptor['sources']):
                filename = '/tmp/i24news{}.tmp'.format(ii)
                url = s['src']
                info('Writing {}'.format(filename))

                with open(filename, 'w') as f:
                    rr = self.network.get(url, headers, render=False)
                    f.write(MyNetwork.get_text_content(rr))

        def show(url):
            r = self.network.get(url, self.i24news_accept_json_headers, render=False)
            # print(r.headers)
            content = MyNetwork.get_text_content(r)
            j = json.loads(content)

            def show_container(j):
                # pprint(json.loads(content))
                # page key describes containerId list
                # container key describes sections with itemId list that refers to item
                # item key includes id field corresponding to container['itemId[#]'] with attributes that include own itemId.
                if 'container' in j:
                    for d in j['container']:
                        if 'title' in d and 'itemId' in d and 'id' in d:
                            print("title: {}  count: {}  id {}".format(d['title'], len(d['itemId']), d['id']))
                        else:
                            print('unknown structure: ')
                            pprint(d)

            def show_items(j, itemIds=None):
                display = []
                if 'item' in j:
                    for d in j['item']:
                        if itemIds is None or d['id'] in itemIds:
                            if 'attributes' in d:
                                title = 'unknown'
                                assetId = 'unknown'
                                duration = 'unknown'
                                available_date = ''
                                published_date = ''
                                description = ''
                                for a in d['attributes']:
                                    k = a['key']
                                    v = a['value']
                                    if k == 'title':
                                        title = v
                                    elif k == 'assetId':
                                        assetId = v
                                    elif k == 'video-duration':
                                        duration = v
                                    elif k == 'description':
                                        description = v
                                    elif k == 'availableDate':  # timestamp
                                        available_date = v
                                    elif k == 'publishedDate':  # timestamp
                                        published_date = v

                                display.append(
                                        dict(
                                            title=title,
                                            description=description,
                                            id=d['id'],
                                            assetId=assetId,
                                            duration=duration,
                                            available_date=available_date,
                                            published_date=published_date
                                            )
                                        )
                            else:
                                print('unknown structure: ')
                                pprint(d)

                if len(display) > 0:
                    while True:
                        for ii, val in enumerate(display):
                            print("{}. {}".format(ii, val['title']))

                        selection = input('Selection? ')
                        try:
                            selection = int(selection)
                            if selection in range(len(display)):
                                print('Trying to play asset ID {} with title "{}"'.format(display[selection]['assetId'],
                                                                                          display[selection]['title']))
                                return display[selection]['assetId']
                            else:
                                break
                        except ValueError:
                            print('Please select the line item number.')
                else:
                    print('No items to display')

            return show_items(j)

        menu_items = [
            'Live',
            'News',
            'TV Shows',
            'Quit'
        ]

        def menu():
            while True:
                print('Menu')
                for ii, val in enumerate(menu_items):
                    print("{}. {}".format(ii, val))
                selection = input('Numeric selection? ')
                try:
                    selection = int(selection)
                except ValueError:
                    print('Please select the line item number.')
                if selection in range(len(menu_items)):
                    return selection
                else:
                    print('Invalid selection.')

        while True:
            selection = menu()

            assetId = None
            if menu_items[selection] == 'Live':
                assetId = show(
                    'https://video.i24news.tv/proxy/page/live?appId=5a8452d11de1c4000c77c692&uuid={}'.format(self.uuid))
            elif menu_items[selection] == 'News':
                assetId = show(
                    'https://video.i24news.tv/proxy/page/news?appId=5a8452d11de1c4000c77c692&uuid={}'.format(self.uuid))
            elif menu_items[selection] == 'TV Shows':
                assetId = show(
                    'https://video.i24news.tv/proxy/page/tv-shows?appId=5a8452d11de1c4000c77c692&uuid={}'.format(
                        self.uuid))
            elif menu_items[selection] == 'Quit':
                sys.exit(0)

            if assetId is not None:
                pk = get_policy_key()
                if len(pk) > 0:
                    verbose("Using policy key " + pk)
                    descriptor = get_brightcove(assetId, pk)

                    # Stream m3u (typically) directly with external app
                    stream_media(descriptor)

                    # Previously saved all of the descriptor files, but the issue was that some m3u files referred to
                    # sources with URL paths only, excluding the domain, which means the domain defaults to the place
                    # where the m3u file was accessed.
                    # save_media_sources(descriptor)
                else:
                    error('Could not find policy key')
            else:
                error('No asset ID returned')


@click.command()
@click.option('-v', '--verbose', count=True)
@click.option('--credentials', default="credentials.json", show_default=True, type=click.Path(exists=True))
def main(verbose, credentials):
    global log_level
    if verbose == 1:
        log_level = INFO
    elif verbose > 1:
        log_level = VERBOSE

    requests_session = HTMLSession()
    streamer = NewsStreamer(requests_session, credentials)
    streamer.auth()
    streamer.show_menu()


if __name__ == '__main__':
    main()
