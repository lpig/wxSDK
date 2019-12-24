import hmac
import time
import arrow
import requests
import hashlib
from hashlib import md5
from urllib import parse

from django.conf import settings
from django.utils.crypto import get_random_string

from kol.locked import Lock
from kol.utils import rds, log, aliyun_oss_upload, aliyun_oss_exists, arrayToXml, xmlToArray
from member.models import UserPay


class HttpResult(object):
    def __init__(self, result):
        self.result = {}
        self.code = 0
        self.msg = 'Success'
        self.check_http_message(result)

    def check_http_message(self, data):
        """
        处理错误信息
        :param data:
        :return:
        """
        if data.status_code != 200:
            # log.info
            self.code = data.status_code
            self.msg = data.text
            return self.code, self.msg

        self.result = data = data.json()

        if data.get("errcode", None):
            self.code = data.get('errcode')
            self.msg = data.get('errmsg')
            return self.code, self.msg
        return self.code, self.msg


class XAppSDK(object):
    """
    微信小程序SDK
    """

    appid = settings.XAPP_APPID
    secret = settings.XAPP_SECRET
    access_token_lock_key = 'kol_server_access_token_lock_{0}'
    access_token_cache_key = 'kol_server_access_token_{0}'

    def __init__(self, **kwargs):
        if 'appid' in kwargs:
            self.appid = kwargs.get('appid')
            self.secret = kwargs.get('secret')

        self.access_token_lock_key = self.access_token_lock_key.format(self.appid)
        self.access_token_cache_key = self.access_token_cache_key.format(self.appid)

    def _get(self, url, params=None):
        result = requests.get(url, params=params)
        return HttpResult(result)

    def _post(self, url, data):
        result = requests.post(url, json=data)
        return HttpResult(result)

    def get_access_token(self):
        token = rds.get(self.access_token_cache_key)

        if not token:
            with Lock.get_lock(self.access_token_lock_key, expire=15):
                token = rds.get(self.access_token_cache_key)
                if not token:
                    url = 'https://api.weixin.qq.com/cgi-bin/token'

                    params = {
                        "grant_type": "client_credential",
                        "appid": self.appid,
                        "secret": self.secret,
                    }

                    r = self._get(url, params)

                    if r.code != 0:
                        log.error(f'微信获取token失败, code：{r.code}, msg：{r.msg}')
                        return
                    result = r.result

                    token = result.get('access_token')

                    if token is not None:
                        expire_in = result.get('expires_in', 7200) - 60
                        rds.set(self.access_token_cache_key, token)
                        rds.expire(self.access_token_cache_key, expire_in)

        if not isinstance(token, str):
            token = token.decode()

        return token

    @property
    def access_token(self):
        return self.get_access_token()

    def get_qr_code(self, scene, page=None):
        """
        获取小程序二维码
        :param scene:
        :param page:
        :return:
        """
        url = f'https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token={self.access_token}'

        md5_data = data = {
            "scene": scene,
            "page": page,
        }

        md5_data.update({"appid": self.appid})
        _key = parse.urlencode(md5_data)
        _key = md5(_key.encode()).hexdigest()
        _path = f'qrcode/{_key}.jpg'

        if not aliyun_oss_exists(_path):
            r = requests.post(url, json=data)
            try:
                _info = r.json()
                errcode = _info.get('errcode')
                errmsg = _info.get('errmsg')

                log.error(f'生成微信二维码错误, code: {errcode}, msg: {errmsg}')
                return None
            except:
                pass
            _info = r.content

            _key = _path
            aliyun_oss_upload(_key, _info, public_read=True)

        url = f"{settings.ALIYUN_OSS_CDN_NAME}{_path}"
        return url

    def get_qr_code_another(self, path):
        """
        获取小程序二维码
        路径长度不限 有数量限制
        :param path:
        :return:
        """
        url = f'https://api.weixin.qq.com/wxa/getwxacode?access_token={self.access_token}'

        md5_data = data = {
            'path': path,
        }

        md5_data.update({"appid": self.appid})
        _key = parse.urlencode(md5_data)
        _key = md5(_key.encode()).hexdigest()
        _path = f'qrcode/{_key}.jpg'

        if not aliyun_oss_exists(_path):
            r = requests.post(url, json=data)
            try:
                _info = r.json()
                errcode = _info.get('errcode')
                errmsg = _info.get('errmsg')

                log.error(f'生成微信二维码错误, code: {errcode}, msg: {errmsg}')
                return None
            except:
                pass
            _info = r.content

            _key = _path
            aliyun_oss_upload(_key, _info, public_read=True)

        url = f"{settings.ALIYUN_OSS_CDN_NAME}{_path}"
        return url

    def send_template(self, data):
        """
        发送模板消息
        :param data:
        :return:
        """
        url = f'https://api.weixin.qq.com/cgi-bin/message/wxopen/template/send?access_token={self.access_token}'

        r = self._post(url, data)

        return r


class WXPay(object):
    """
    微信支付sdk
    """

    mch_id = settings.WXPAY_MCHID
    secret = settings.WXPAY_SECRET
    sign_type = 'MD5'

    def __init__(self, appid, **kwargs):
        self.appid = appid

        for k, v in kwargs.items():
            if k and v:
                setattr(self, k, v)

    def _post(self, url, data):

        headers = {
            'Content-Type': "text/xml",
        }

        result = requests.post(url, data=data.encode('utf-8'), headers=headers)
        if result.status_code != 200:
            log.error(f'请求微信接口网络错误 code: {result.status_code}, msg: {result.text}')
            return None

        content = result.content
        data = xmlToArray(content)

        return_code = data.get('return_code')
        if return_code != 'SUCCESS':
            return_msg = data.get('return_msg')
            log.error(f'微信错误 msg: {return_msg}')
            return None

        result_code = data.get('result_code')
        if result_code != 'SUCCESS':
            err_code = data.get('err_code')
            err_code_des = data.get('err_code_des')
            log.error(f'调用接口出错 code: {err_code}, msg: {err_code_des}')
            return

        return data

    def _get_sign(self, data):
        """
        签名加密功能
        :param data:
        :return:
        """
        _temp_string = []
        for k in sorted(data.keys()):
            _info = data.get(k)
            _temp_string.append(f'{k}={_info}')

        sign = '&'.join(_temp_string)

        sign = f'{sign}&key={self.secret}'

        if self.sign_type == 'MD5':
            sign = md5(sign.encode()).hexdigest().upper()
        elif self.sign_type == 'HMAC-SHA256':
            sign = hmac.new(self.secret.encode(), msg=sign.encode(), digestmod=hashlib.sha256).hexdigest().upper()
        else:
            raise TypeError(f'sign_type {self.sign_type} not support !!')

        return sign

    def unifiedorder(self, total_fee, spbill_create_ip, out_trade_no, trade_type='JSAPI', openid=None, notify_url=None):
        """
        统一下单功能
        :param total_fee:
        :param spbill_create_ip:
        :param trade_type:
        :return:
        """
        scene_info = None
        url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'

        if not notify_url:
            notify_url = f'http://{settings.HOST}/member/wxpaycallback/'

        if trade_type == 'MWEB':
            scene_info = {
                "h5_info": {
                    "type": "支付",
                    "wap_url": "www.kol.com",  # WAP网站URL地址
                    "wap_name": "爱豆星球",
                },
            }

        data = {
            "appid": self.appid,
            "mch_id": self.mch_id,
            "nonce_str": get_random_string(32),
            "sign_type": self.sign_type,
            "body": 'kol星球会员',
            "out_trade_no": out_trade_no,
            "total_fee": str(total_fee),
            "spbill_create_ip": spbill_create_ip,  # 用户IP
            "notify_url": notify_url,  # 回调地址
            "trade_type": trade_type,  # 交易类型 JSAPI-JSAPI支付（或小程序支付）、APP-app支付，MWEB-H5支付
        }

        if scene_info:
            data.update({"scene_info": scene_info})
        if trade_type == 'JSAPI':
            data.update({"openid": openid})

        sign = self._get_sign(data)

        data.update({"sign": sign})
        data = arrayToXml(data)

        req = self._post(url, data=data)
        if not req:
            return

        prepay_id = req.get('prepay_id')
        return prepay_id

    def pay_info(self, total_fee, spbill_create_ip, user, type, trade_type='JSAPI', notify_url=None, info=None,
                 openid=None):
        """
        调起支付
        :param total_fee:
        :param spbill_create_ip:
        :param user:
        :param type:
        :param trade_type:
        :param notify_url:
        :param info:
        :param openid:
        :return:
        """
        out_trade_no = arrow.now(settings.TIME_ZONE).format('YYYYMMDDHHmmss')
        out_trade_no = f'{out_trade_no}{get_random_string(6)}'
        timeStamp = arrow.now(settings.TIME_ZONE).timestamp

        if openid:
            _openid = openid
        else:
            _openid = user.openid

        prepay_id = self.unifiedorder(total_fee, spbill_create_ip, out_trade_no, trade_type=trade_type, openid=_openid,
                                      notify_url=notify_url)
        if not prepay_id:
            log.error(f'获取统一下单出错')
            return

        user_pay = UserPay(user=user)
        user_pay.openid = _openid
        user_pay.type = type
        user_pay.out_trade_no = out_trade_no
        user_pay.price = total_fee
        user_pay.info = info
        user_pay.save()

        data = {
            "appId": self.appid,
            "timeStamp": str(timeStamp),
            "nonceStr": get_random_string(16),
            "package": f"prepay_id={prepay_id}",
            "signType": self.sign_type,
        }

        if trade_type == 'APP':
            data = {
                "appid": self.appid,
                "timestamp": str(timeStamp),
                "noncestr": get_random_string(16),
                "partnerid": self.mch_id,
                "prepayid": prepay_id,
                "package": "Sign=WXPay",
            }

        paySign = self._get_sign(data)

        data.update({
            "paySign": paySign,
        })

        return data


class WXSDK(object):
    access_token_lock_key = 'wxmp_access_token_lock_{0}'
    access_token_cache_key = 'wxmp_access_token_{0}'

    jsapi_ticket_lock_key = 'wxmp_jsapi_ticket_lock_{0}'
    jsapi_ticket_cache_key = 'wxmp_jsapi_ticket_{0}'

    base_url = 'https://api.weixin.qq.com/cgi-bin/'

    def __init__(self):
        self.appid = settings.WXMP_APPID
        self.secret = settings.WXMP_SECRET

    def _get(self, url, params=None):
        result = requests.get(url, params=params)
        return HttpResult(result)

    def _post(self, url, data):
        result = requests.post(url, json=data)
        return HttpResult(result)

    def get_access_token(self):
        token = rds.get(self.access_token_cache_key)

        if not token:
            with Lock.get_lock(self.access_token_lock_key, expire=15):
                token = rds.get(self.access_token_cache_key)
                if not token:
                    url = f'{self.base_url}token'

                    params = {
                        "grant_type": "client_credential",
                        "appid": self.appid,
                        "secret": self.secret
                    }

                    r = self._get(url, params=params)

                    if r.code != 0:
                        log.error(f'微信获取token失败, code：{r.code}, msg：{r.msg}')
                        return
                    result = r.result

                    token = result.get('access_token')

                    if token is not None:
                        expire_in = result.get('expires_in', 7200) - 60
                        rds.set(self.access_token_cache_key, token)
                        rds.expire(self.access_token_cache_key, expire_in)

        if not isinstance(token, str):
            token = token.decode()
        return token

    def get_jsapi_ticket(self):
        ticket = rds.get(self.jsapi_ticket_cache_key)

        if not ticket:
            with Lock.get_lock(self.jsapi_ticket_lock_key, expire=15):
                ticket = rds.get(self.jsapi_ticket_cache_key)
                if not ticket:
                    url = f'{self.base_url}ticket/getticket'

                    params = {
                        "access_token": self.access_token,
                        "type": 'jsapi',
                    }

                    r = self._get(url, params=params)

                    if r.code != 0:
                        log.error(f'微信获取jsapi_ticket失败, code：{r.code}, msg：{r.msg}')
                        return
                    result = r.result

                    ticket = result.get('ticket')

                    if ticket is not None:
                        expire_in = result.get('expires_in', 7200) - 60
                        rds.set(self.jsapi_ticket_cache_key, ticket)
                        rds.expire(self.jsapi_ticket_cache_key, expire_in)

        if not isinstance(ticket, str):
            ticket = ticket.decode()
        return ticket

    @property
    def access_token(self):
        return self.get_access_token()

    @property
    def jsapi_ticket(self):
        return self.get_jsapi_ticket()

    def get_jsapi_ticket_signature(self, url):
        url = parse.unquote_plus(url)
        timestamp = int(time.time())
        noncestr = get_random_string(32)

        signature = f'jsapi_ticket={self.jsapi_ticket}&noncestr={noncestr}&timestamp={timestamp}&url={url}'
        signature = hashlib.sha1(signature.encode()).hexdigest()

        data = {
            "appId": self.appid,
            "timestamp": timestamp,
            "nonceStr": noncestr,
            "signature": signature,
        }
        return data

    def get_userid(self, code):
        url = 'https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo'

        params = {
            "access_token": self.access_token,
            "code": code,
        }

        r = self._get(url, params=params)
        return r

    def get_user_info(self, userid):
        url = 'https://qyapi.weixin.qq.com/cgi-bin/user/get'

        params = {
            "access_token": self.access_token,
            "userid": userid,
        }

        r = self._get(url, params=params)
        return r

    def get_department(self, id):
        url = 'https://qyapi.weixin.qq.com/cgi-bin/department/list'

        params = {
            "access_token": self.access_token,
            "id": id,
        }

        r = self._get(url, params=params)
        return r


wx_sdk = WXSDK()
xapp_sdk = XAppSDK()
