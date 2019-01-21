import collections
import base64
import urllib.parse
from hashlib import sha1, md5
import hmac
from time import time
from random import randint
import json

import requests
import rsa


def sign_data(private_key_str, data):
    """
    param: private_key_loc Path to your private key
    param: package Data to be signed
    data: type: str
    return: base64 encoded signature
    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from base64 import b64encode, b64decode
    key = b64decode(private_key_str)
    rsakey = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    # It's being assumed the data is base64 encoded, so it's decoded before updating the digest
    # digest.update(b64decode(data))
    # sign = signer.sign(digest)
    digest.update(data.encode())
    sign = signer.sign(digest)
    return b64encode(sign)


def verify_sign(public_key_str, signature, data):
    """
    Verifies with a public key from whom the data came that it was indeed
    signed by their private key
    param: public_key_loc Path to public key
    param: signature String signature to be verified
    data: type:str
    return: Boolean. True if the signature is valid; False otherwise.
    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from base64 import b64decode
    pub_key = b64decode(public_key_str)
    rsakey = RSA.importKey(pub_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data.encode())
    if signer.verify(digest, b64decode(signature)):
        return True
    return False


# 获取私钥
def get_private_key():
    with open('/Users/willer/code/python/hms_demo/private.pem', 'r') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())
    return privkey


# 华为登录校验
class GameCPService(object):
    def __init__(self, baseUrl, method, appId, cpId, ts, playerId, playerLevel, playerSSign, privateKey):
        self.baseUrl = baseUrl
        self.method = method
        self.appId = appId
        self.cpId = cpId
        self.ts = ts
        self.playerId = playerId
        self.playerLevel = playerLevel
        self.playerSSign = playerSSign
        self.privateKey = privateKey
        # self.publicKey = publicKey

    # 构造原串
    @staticmethod
    def urlencode(dict_obj):
        urlencode_str = urllib.parse.urlencode(dict_obj)
        return urlencode_str

    # 排序字典
    @staticmethod
    def sorted_dict(params_dict):
        params_dict = collections.OrderedDict(sorted(params_dict.items()))
        return params_dict

    # 生成签名值RSA with SHA256 对签名使用BASE64加密
    def make_rsa(self, urlencode_str):
        urlencode_bytes = urlencode_str.encode()
        signature = rsa.sign(urlencode_bytes, self.privateKey, 'SHA-256')
        cpSign = base64.b64encode(signature).decode()
        return cpSign

    # 1.构造排序字典 2.加签 3.重新构造字典增加签名参数 4.发送请求
    def post_request(self):
        params_dict = {
            "method": self.method,
            "appId": self.appId,
            "cpId": self.cpId,
            "ts": self.ts,
            "playerId": self.playerId,
            "playerLevel": self.playerLevel,
            "playerSSign": self.playerSSign
        }
        params_dict_sorted = self.sorted_dict(params_dict)
        params_str = self.urlencode(params_dict_sorted)
        cpSign = self.make_rsa(params_str)
        params_dict_sorted["cpSign"] = cpSign
        hms_response = requests.post(self.baseUrl, data=params_dict_sorted)
        return hms_response

    # 返回值验签（可选）
    def check_result(self):
        pass


# 小米登录校验
class MiCPServer(object):
    def __init__(self, appId, session, uid, AppSecret, url):
        self.appId = appId
        self.session = session
        self.uid = uid
        self.AppSecret = AppSecret
        self.url = url

    # 排序字典
    @staticmethod
    def sorted_dict(params_dict):
        params_dict = collections.OrderedDict(sorted(params_dict.items()))
        return params_dict

    # 拼接参数构造源串，未urlencode编码
    @staticmethod
    def before_signature(params_dict):
        post_str = ""
        for i in params_dict:
            post_str += "{}={}&".format(i, params_dict[i])
        post_str.rstrip("&")
        return post_str

    def make_signature(self, params_dict_sorted):
        post_str = self.before_signature(params_dict_sorted)
        signature = hmac.new(self.AppSecret.encode(), post_str.encode(), sha1).hexdigest()
        return signature

    def post_request(self):
        params_dict = {
            "appId": self.appId,
            "session": self.session,
            "uid": self.uid,
        }
        params_dict_sorted = self.sorted_dict(params_dict)
        signature = self.make_signature(params_dict_sorted)
        params_dict_sorted['signature'] = signature
        mi_response = requests.post(self.url, data=params_dict_sorted)
        return mi_response


# oppo登录校验
class OppoCpServer(object):
    def __init__(self, token, ssoid, baseUrl, appKey, appSecret):
        self.token = urllib.parse.quote_plus(token)  # 接收app发送的token, 需进行urlencode
        self.ssoid = ssoid  # app发给这边
        self.baseUrl = baseUrl
        self.oauthConsumerKey = appKey  # app key
        self.sign = "{}&".format(appSecret)  # appSecret
        self.baseStr = "oauthConsumerKey={}&oauthToken={}&oauthSignatureMethod={}&" \
            "oauthTimestamp={}&oauthNonce={}&oauthVersion={}&".format(
                appKey, token, "HMAC-SHA1", int(time()),
                randint(100000, 999999), "1.0")
        self.request_url = "{}?fileId={}&token=".format(baseUrl, self.ssoid, self.token)

    def make_signature(self):
        signature = hmac.new(self.sign.encode(), self.baseStr.encode(), sha1).hexdigest()
        return urllib.parse.quote_plus(signature.encode())  # 编码

    def get_request(self):
        headers = {"param": self.baseStr, "oauthSignature": self.make_signature()}
        oppo_response = requests.get(self.request_url, headers=headers)
        return oppo_response


# Vivo登录校验
class VivoCpServer(object):
    """
    url: "https://usrsys.vivo.com.cn/sdk/user/auth.do"
    method: "post"
    params: {"authtoken": 登录vivo帐户后获取到的authtoken}
    """
    def __init__(self, authtoken):
        self.url = "https://usrsys.vivo.com.cn/sdk/user/auth.do"
        self.authtoken = authtoken

    def post_request(self):
        vivo_response = requests.post(self.url, data={"authtoken": self.authtoken})
        return vivo_response


# 应用宝登录校验（qq+微信）
class TencentCpServer(object):
    def __init__(self, appid, appkey, openid, openkey, login_type):
        self.appid = appid
        self.openid = openid
        self.openkey = openkey
        timestamp = int(time())
        self.sig = md5("{}{}".format(appkey, timestamp).encode('utf-8')).hexdigest()
        if login_type == "QQ":
            # 测试url
            self.baseurl = "http://ysdktest.qq.com/auth/qq_check_token"
            # 正式环境url
            # self.baseurl = "http://ysdk.qq.com/auth/qq_check_token"
        elif login_type == "WX":
            # 测试url
            self.baseurl = "http://ysdktest.qq.com/auth/wx_check_token"
            # 正式环境url
            # self.baseurl = "http://ysdk.qq.com/auth/wx_check_token "
        else:
            pass
        self.url = "{}?timestamp={}&appid={}&sig={}&openid={}&openkey={}&userip".format(
            self.baseurl, timestamp, appid, self.sig, openid, openkey
        )

    def get_request(self):
        tencent_response = requests.get(self.url)
        return tencent_response


# 百度网游SDK服务端登录状态查询
class BaiduCpServer(object):
    def __init__(self, appid, access_token, secret_key):
        self.Sign = md5((str(appid)+str(access_token)+str(secret_key)).encode()).hexdigest()
        parameter_dict = {"AppID": appid, "AccessToken": access_token, "Sign": self.Sign}
        parameter_str = urllib.parse.urlencode(parameter_dict)
        base_url = "http://query.u.duoku.com/query/cploginstatequery?"
        self.url = "{}{}".format(base_url, parameter_str)

    def get_request(self):
        baidu_response = requests.get(self.url)
        return baidu_response


# 阿里uc九游豌豆荚服务端登录状态查询：
class AliCpServer(object):
    def __init__(self, sid, apiKey):
        self.base_url = "http://sdk.9game.cn/cp/account.verifySession"
        sign = md5((str(sid)+str(apiKey)).encode()).hexdigest()
        self.param_dict = {
            "id": int(time()),
            "data": {"sid": "abcdefg123456"},
            "game": {"gameId": 12345},
            "sign": sign
        }

    def post_request(self):
        ali_response = requests.post(self.base_url, json=json.dumps(self.param_dict))
        return ali_response


if __name__ == '__main__':
    # 华为登录校验测试 测试通过
    privateKey = get_private_key()
    baseUrl = "https://gss-cn.game.hicloud.com/gameservice/api/gbClientApi"
    method = "external.hms.gs.checkPlayerSign"
    appId = "100593059"
    cpId = "80086000024439088"
    ts = 1547620855987  # 时间戳必须在十分钟以内
    playerId = "100"
    playerLevel = "10"
    playerSSign = "VUOoWexHeQC98OFHyWapgKSACDwBgEHWb6IvPutKO0Z/wSVU3SDoK7/vnaLsYte6cYJu/RVWxoGh8lJfHuMoMucKutoNEXnAnPgTG5cfXf79DCtTnhMJ3lHBjaYFD03RWb2XBRKlnF7m455DeU2bvPZOsi7BhTDNPD0bTxY7PWlASLCSX7C7WqHN4/AWxDiU+ki2pPBstuSDecoUQQATBU35bQE2V7DtOsoGAhseuKXZe7yExMqszyZHLKaaqsbqq1rCua6FvJtwlwO82eY7N5kyW29r3MQ/uW1XGh4aPDods9UfD90BSLoPPmLjV9tREX/HFIdxkZ3FVWbkcWR4YQ=="
    server = GameCPService(baseUrl, method, appId, cpId, ts, playerId, playerLevel, playerSSign, privateKey)
    response = server.post_request()
    response.json()

    # 小米登录校验接口测试 测试通过
    # url = "http://mis.migc.xiaomi.com/api/biz/service/loginvalidate"
    # appId = "2882303761517239138"
    # session = "1nlfxuAGmZk9IR2L"
    # uid = "100010"
    # mi_server = MiCPServer(appId, session, uid, AppSecret="b560b14efb18ee2eb8f85e51c5f7c11f697abcfc", url=url)
    # response = mi_server.post_request()
    # response.json()

    # oppo登录校验接口 测试大致通过，仅测试出1002返回码，msg:提示签名错误。
    # baseUrl = "https://iopen.game.oppomobile.com/sdkopen/user/fileIdInfo"
    # token = "TOKEN_mpWEc25NDr2HzRXQAAMFB%2Fd77Rhr3PxePY4W0BC%2BlOBQ%2BwWpf8W%2Fvg%3D%3D"
    # ssoid = "27352387"
    # appKey = "93b014fbe9304920ac9d07e50f5eb91b"
    # appSecret = "2BpBK2Xy9UCCPbhCCpGqQIfE"
    # oppo_server = OppoCpServer(token, ssoid, baseUrl, appKey, appSecret)
    # response = oppo_server.get_request()
    # response.json()

    # vivo登录校验接口 测试通过，返回20002，authtoken失效
    # vivo_server = VivoCpServer("2BpBK2Xy9UCCPbhCCpGqQIfE")
    # vivo_response = vivo_server.post_request()
    # vivo_response.json()

    # 应用宝登录接口  返回200，但appid不存在，无法进一步测试
    # tencent_server = TencentCpServer(100010, "2BpBK2Xy9UCCPbhCCpGqQIfE", 1000, "2BpBK2Xy9UCCPbhCCpGqQIfE", "WX")
    # response = tencent_server.get_request()
    # response.json()

    # 百度登录状态查询接口 返回200， msg 业务系统未通过校验
    # baidu_server = BaiduCpServer(100010, "2BpBK2Xy9UCCPbhCCpGqQIfE", "2BpBK2Xy9UCCPbhCCpGqQIfE")
    # baidu_response = baidu_server.get_request()
    # baidu_response.json()

    # 阿里登录状态查询接口 status:200 错误码10 接口文档中说10为内容格式有误或gameid错误，或签名校验失败
    # ali_server = AliCpServer("abcdefg123456", "202cb962234w4ers2aaa")
    # ali_response = ali_server.post_request()
    # response_dict = ali_response.json()

