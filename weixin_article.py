import requests
import time,datetime
import re
import json
import urllib.parse
import os
import pdfkit
class weixin:
    #QQ号码
    _qq_num = -1
    #QQ密码
    _qq_psw = ''

    #二维码图片位置
    _qrc_dir = ''
    _state_url = ''
    _login_sig_cookie = None
    _ptcz = None

    #获取微信的信令
    _sign = dict()

    #微信号的名称
    _weixin_info = list()

    def __init__(self,qq_num,qq_psw):
        self._qq_num = qq_num
        self._qq_psw = qq_psw
        pass

    def __init__(self,qrc_dir):
        self._qrc_dir = qrc_dir
        pass
    def login(self):
        '''
        登陆搜狗微信
        :return:
        '''
        self._state_url = self._get_parameter_url()

        login_sig = self._get_login_sig()
        self._login_sig_cookie = login_sig

        res = self._get_qrc()

        self._qrc_scan(res.get('qrsig'))
        return

    def _get_parameter_url(self):
        '''
        获取重定向参数地址，
        :return:
        '''
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host':'account.sogou.com',
                   'Referer':'http://weixin.sogou.com/',
                   'Upgrade-Insecure-Request':'1',
                   'Cookie':'IPLOC=CN1100; SUID=255A48DF5F20940A0000000058A65384; SUV=00947A5EDF485A2558A65384E56CE626'
        }
        url = 'https://account.sogou.com/connect/login?provider=qq&client_id=2017&ru=http://weixin.sogou.com/pcindex/login/qq_login_callback_page.html&hun=0&oa=0'

        r = requests.get(url=url,headers=headers,allow_redirects=False)

        print("重定向地址："+str(r.headers['Location']))
        return r.headers['Location']

    def _get_parameter(self, url, name):
        '''
        获取url的参数，主要是state
        :param url:
        :param name:
        :return:
        '''
        pa_str = '[\?|&]+' + name + '=([^&]*)(&|$)'
        result = re.search(pa_str, url)
        if result:
            print('获取'+name+'参数：'+result.group(1))
            return result.group(1)
        return ''

    def _get_login_sig(self):
        '''
        获取登录信令
        :return:
        '''
        url = 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&pt_no_auth=1&style=33&login_text=授权并登录&hide_title_bar=1&hide_border=1&target=self&s_url=https://graph.qq.com/oauth/login_jump&pt_3rd_aid=100294784&pt_feedback_link=http://support.qq.com/write.shtml?fid=780&SSTAG=www.sogou.com.appid100294784'

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host':'xui.ptlogin2.qq.com',
                   'Referer':self._state_url
                   }
        r = requests.get(url, headers=headers)
        return r.cookies
    def _get_qrc(self):
        '''
        获取二维码图片
        :return:
        '''
        url = 'https://ssl.ptlogin2.qq.com/ptqrshow?appid=716027609&e=2&l=M&s=3&d=72&v=4&t=0.21636327833315416&daid=383'
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host': 'ssl.ptlogin2.qq.com',
                   'Referer': 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&pt_no_auth=1&style=33&login_text=%E6%8E%88%E6%9D%83%E5%B9%B6%E7%99%BB%E5%BD%95&hide_title_bar=1&hide_border=1&target=self&s_url=https%3A%2F%2Fgraph.qq.com%2Foauth%2Flogin_jump&pt_3rd_aid=100294784&pt_feedback_link=http%3A%2F%2Fsupport.qq.com%2Fwrite.shtml%3Ffid%3D780%26SSTAG%3Dwww.sogou.com.appid100294784'

                   }
        response = requests.get(url,headers = headers)
        png = open(self._qrc_dir,'wb')
        if png:
            png.write(response.content)
            png.close()

        return response.cookies

    def _qrc_scan(self,qrsig):
        '''
        监听扫描二维码的结果
        :param qrsig:
        :return:
        '''
        url = 'https://ssl.ptlogin2.qq.com/ptqrlogin?u1=https://graph.qq.com/oauth/login_jump&ptqrtoken='
        url += self._hash_33(qrsig)+'&ptredirect=0&h=1&t=1&g=1&from_ui=1&ptlang=2052&action=0-0-'
        url += self._get_now_date()
        url += '&js_ver=10194&js_type=1&login_sig='
        url += self._login_sig_cookie.get('pt_login_sig')+'&pt_uistyle=40&aid=716027609&daid=383&pt_3rd_aid=100294784&'

        print('二维码图片地址->'+url)

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host': 'ssl.ptlogin2.qq.com',
                   'Referer': 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&pt_no_auth=1&style=33&login_text=%E6%8E%88%E6%9D%83%E5%B9%B6%E7%99%BB%E5%BD%95&hide_title_bar=1&hide_border=1&target=self&s_url=https%3A%2F%2Fgraph.qq.com%2Foauth%2Flogin_jump&pt_3rd_aid=100294784&pt_feedback_link=http%3A%2F%2Fsupport.qq.com%2Fwrite.shtml%3Ffid%3D780%26SSTAG%3Dwww.sogou.com.appid100294784'
                   }
        cookies = {
            'qrsig':qrsig,
            'pt_login_sig':self._login_sig_cookie.get('pt_login_sig'),
            'pt_clientip': self._login_sig_cookie.get('pt_clientip'),
            'pt_guid_sig':self._login_sig_cookie.get('pt_guid_sig'),
            'pt_serverip': self._login_sig_cookie.get('pt_serverip'),
            'uikey': self._login_sig_cookie.get('uikey')
        }

        while 1:
            r = requests.get(url,headers=headers,cookies=cookies)
            #print(r.text)
            if 200 != r.status_code:
                break
            res = self._parse_scan_result(r.content)

            if 0 == res[0]:
                print('扫描成功->'+str(r.cookies))
                self._ptcz=r.cookies['ptcz']
                self._check_sig(res[1])
                return
            time.sleep(1)
        pass

    def _check_sig(self,url):
        '''
        检查登录信令，并尝试登陆
        :param url: 检查登录信令地址
        :return:
        '''
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host': 'ssl.ptlogin2.graph.qq.com',
                   }
        r = requests.get(url,allow_redirects=False,headers=headers)
        print('1--->检查信令')
        print(r.headers)
        self._login_jump(r.cookies, r.headers['Location'])

        post_authorize = self._post_authorize(r.cookies)

        if post_authorize:
            result = self._qq2sogou(post_authorize)
            self._get_ppmdig(result)

        pass


    def _login_jump(self,cookies,url):
        '''
        登陆成功后跳转的信息
        :param cookie:
        :param url:
        :return:
        '''
        send_cookie = {'p_skey': cookies.get('p_skey'),
                       'pt4_token': cookies.get('pt4_token'),
                       'ptcz': self._ptcz,
                       'ui': 'D772C0F8-8758-4FE3-9B18-A82897931711',
                       'pt2gguin': cookies.get('pt2gguin'),
                       'skey': cookies.get('skey')
                       }
        send_header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                       'Accpet': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                       'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                       'Accpet-Encoding': 'gzip, deflate, br',
                       'Host': 'graph.qq.com',
                       'Upgrade-Insecure-Request': '1',
                       #'Content-Type': 'application/x-www-form-urlencoded',
                       #'Content-Length': '473',
                       'Referer': 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&pt_no_auth=1&style=33&login_text=%E6%8E%88%E6%9D%83%E5%B9%B6%E7%99%BB%E5%BD%95&hide_title_bar=1&hide_border=1&target=self&s_url=https%3A%2F%2Fgraph.qq.com%2Foauth%2Flogin_jump&pt_3rd_aid=100294784&pt_feedback_link=http%3A%2F%2Fsupport.qq.com%2Fwrite.shtml%3Ffid%3D780%26SSTAG%3Dwww.sogou.com.appid100294784'

                       }
        print('login-jump---->')
        r = requests.get(url,cookies=send_cookie,headers=send_header)
        print(r.text)
        pass
    def _post_authorize(self,cookies):
        '''
        取得跳转链接地址
        :param cookies:
        :return:
        '''
        post_url = 'https://graph.qq.com/oauth2.0/authorize'
        post_cookie = {'p_skey': cookies.get('p_skey'),
                       'pt4_token': cookies.get('pt4_token'),
                       'ptcz': self._ptcz,
                       'ui': 'D772C0F8-8758-4FE3-9B18-A82897931711',
                       'pt2gguin': cookies.get('pt2gguin'),
                       'skey': cookies.get('skey'),
                       'ptisp':'cm',
                       'uin':cookies.get('pt2gguin'),
                       'p_uin':cookies.get('pt2gguin')
                       }
        post_data = {
            'response_type': 'code',
            'client_id': '100294784',
            'redirect_uri': 'https://account.sogou.com/connect/callback/qq?client_id=2017&ip=223.72.90.37&ru=http%253A%252F%252Fweixin.sogou.com%252Fpcindex%252Flogin%252Fqq_login_callback_page.html&type=web'
            , 'scope': 'get_user_info,get_app_friends',
            'state': self._get_parameter(self._state_url, 'state'),
            'src': '1',
            'update_auth': '1',
            'openapi': '80901010_1030',
            'g_tk': self._get_token(cookies.get('skey')),
            'auth_time': self._get_now_date(),
            'ui': 'D772C0F8-8758-4FE3-9B18-A82897931711'
        }

        post_header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                       'Accpet': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                       'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                       'Accpet-Encoding': 'gzip, deflate, br',
                       'Host': 'graph.qq.com',
                       'Upgrade-Insecure-Request': '1',
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'Content-Length': '473',
                       'Referer': 'https://graph.qq.com/oauth/show?which=ConfirmPage&display=pc&scope=get_user_info%2Cget_app_friends&response_type=code&show_auth_items=0&redirect_uri=https%3A%2F%2Faccount.sogou.com%2Fconnect%2Fcallback%2Fqq%3Fclient_id%3D2017%26ip%3D223.72.90.37%26ru%3Dhttp%25253A%25252F%25252Fweixin.sogou.com%25252Fpcindex%25252Flogin%25252Fqq_login_callback_page.html%26type%3Dweb&state=' + self._get_parameter(
                           self._state_url, 'state') + '&client_id=100294784'
                       }
        print('post-data->' + str(post_data))
        print('post-header->' + str(post_header))
        print('post-cookie->' + str(post_cookie))
        r = requests.post(post_url, headers=post_header, cookies=post_cookie, data=post_data, allow_redirects=False)
        if 302 !=r.status_code:
            return None

        print('post_authorize---->')
        print(r.status_code)
        print(r.headers)
        #code = self._get_parameter(r.headers['Location','code'])
        return r.headers['Location']

    def _qq2sogou(self,url):
        '''
        获取登录搜狗的cookie
        :param url:
        :return:
        '''
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
                   'Accpet': '*/*',
                   'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accpet-Encoding': 'gzip, deflate, br',
                   'Host': 'account.sogou.com',
                   'Referer': self._state_url
                   }
        qq_callback_cookies = {'IPLOC': 'CN',
                               'SUID': '255A48DF5F20940A0000000058A52476',
                               'SUV': '00F95AA5DF485A2558A524805DA9A538'
                               }
        r = requests.get(url, headers=headers, cookies=qq_callback_cookies, allow_redirects=False)
        print('qq2sogou---->')
        print(r.status_code)
        print(r.headers)
        print(r.cookies)
        self._sign['ppinf'] = r.cookies.get('ppinf')
        self._sign['pprdig'] = r.cookies.get('pprdig')
        return r.cookies

    def _get_ppmdig(self,cookies):
        '''
        获取ppmdig的cookie
        :param cookie:
        :return:
        '''

        qq_login_callback_cookie = {'ppinf':cookies.get('ppinf'),
                                    'pprdig':cookies.get('pprdig'),
                                    'weixinIndexVisited':'1'
        }
        r = requests.get('http://weixin.sogou.com/pcindex/login/qq_login_callback_page.html',
                     cookies=qq_login_callback_cookie)
        print('4---->')
        print(r.cookies)
        self._sign['ppmdig'] = r.cookies.get('ppmdig')
        return r.cookies

    def _hash_33(self,qrsig):
        '''
        获取hash码
        :param qrsig:
        :return:
        '''
        e = 0
        for item in qrsig:
            e += (e << 5) + ord(item)

        e = 2147483647 & e

        return str(e)

    def _get_token(self,skey):
        hash = 5381
        for item in skey:
            hash += (hash << 5) + ord(item)
        return hash & 0x7fffffff

    def _parse_scan_result(self,content):
        '''
        解析二维码扫描后的结果
        :param content:
        :return:
        '''
        res = str(content).split("\',\'")
        tmp = res[0]
        lst = list()
        lst.append(int(tmp[10:]))
        if 0 == lst[0]:
            lst.append(res[2])
        return lst

    def save(self,name,dir):
        self._weixin_info = self._get_open_list()
        articles = self._get_article_list(name)
        self._save_article(articles,dir,name)
        pass

    def _save_article(self,articles,dir,name):
        where = dir + '\\' + name
        if False ==os.path.exists(where):
            os.makedirs(where)
        for item in articles:
            url = item['url']
            print(url)
            a = where + '\\' + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(int(item['lastmodified'])))+'.pdf'
            print(a)
            pdfkit.from_url(item['url'], a)
            time.sleep(0.5)
        pass
    def _get_open_list(self):
        '''
        获取所有关注的微信公众号的信息
        :return:
        '''
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
            'Accpet': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accpet-Encoding': 'gzip, deflate, br',
            'Host': 'weixin.sogou.com',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'http://weixin.sogou.com/home?stype=3'
        }
        cookie = {
            'SUID': '255A48DF2930990A0000000058A80B67',
            'SUV': '00E15AA1DF485A2558A80B694C1A1996',
            'ppinf': self._sign['ppinf'],
            'ppmdig': self._sign['ppmdig'],
            'pprdig': self._sign['pprdig'],
            'weixinIndexVisited': '1',
            'IPLOC': 'CN'
        }
        url = 'http://weixin.sogou.com/remind/openid_list.php?callback=jQuery1110000507062576002415_' + self._get_now_date() + '&from=web&uid=F2BD0B2D7FB7E6A81A3F385D6EA8D972@qq.sohu.com&isupdateclear=1&_=1487414787836'
        r = requests.get(url=url, headers=header, cookies=cookie)
        print(r.text)
        if 200 != r.status_code:
            return
        openid_list = re.search('(jQuery[\d_]+)\((\{.*\})\)',r.text).group(2)
        s = json.loads(openid_list)
        return s['content']

    def _get_article_list(self,name):
        '''
        根据名字获取所有的历史文章列表
        :param name:
        :return:
        '''
        oi = -1
        for item in self._weixin_info:
            if(item['sourcename'] == name):
                oi = int(item['openidid'])
            pass
        if -1 == oi:
            return
        url = 'http://weixin.sogou.com/home?stype=3&ie=utf-8&'+str(urllib.parse.urlencode({'query':name}))+'&oi='+str(oi)
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0",
            'Accpet': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accpet-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accpet-Encoding': 'gzip, deflate, br',
            'Host': 'weixin.sogou.com',
            'Referer': url,
            #'Upgrade-Insecure-Request':1
            'X-Requested-With': 'XMLHttpRequest'
        }
        cookie = {
            'SUID': '255A48DF2930990A0000000058A80B67',
            'SUV': '00E15AA1DF485A2558A80B694C1A1996',
            'ppinf': self._sign['ppinf'],
            'ppmdig': self._sign['ppmdig'],
            'pprdig': self._sign['pprdig'],
            'weixinIndexVisited': '1',
            'IPLOC': 'CN'
        }
        payload={
            'callback':'jQuery1110000507062576002415_' + self._get_now_date(),
            'from':'web',
            'uid':'F2BD0B2D7FB7E6A81A3F385D6EA8D972@qq.sohu.com',
            'openidid':oi,
            'start':'0',
            'num':'10',
            'clear':'1',
            '_':self._get_now_date()
        }
        print(header)

        r = requests.get(url = 'http://weixin.sogou.com/remind/doc_list_openid.php',params=payload,headers=header,cookies=cookie)
        print(r.text)
        if 200 != r.status_code:
            return
        m = re.search('(jQuery[\d_]+)\((\{.*\})\)', r.text).group(2)
        s = json.loads(m)
        total_num = int(s['totalnum'])
        article_list = s['content']
        for item in range(10,total_num,10):
            payload['start'] = item
            payload['_'] = self._get_now_date()
            r = requests.get(url='http://weixin.sogou.com/remind/doc_list_openid.php', params=payload, headers=header,
                             cookies=cookie)
            print(r.text)
            if 200 != r.status_code:
                return
            m = re.search('(jQuery[\d_]+)\((\{.*\})\)', r.text).group(2)
            s = json.loads(m)
            article_list.extend(s['content'])
            time.sleep(1)
            pass

        return article_list

    def _get_now_date(self):
        return str(int(time.mktime(datetime.datetime.now().timetuple())*1000))
