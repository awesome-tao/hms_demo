import logging
from flask import request, jsonify
from urllib.parse import unquote_plus

from app.hms_api import hms_api
from app.hms_api.utils import GameCPService, get_private_key, verify_sign



logging.basicConfig(filename='example.log', level=logging.DEBUG)
# 如果每个商店流程都是大同小异，只是参数区别，那么应该将流程单独提出来作为一个视图函数或者方法，将参数的构造进行区分
# 先单独写，再整合

# 校验登录签名接口的步骤
# 1、接收app请求，解析参数 2、构造发送给华为服务器的post参数 3、对参数用私钥生成签名值 4、将签名值和参数都post过去
# 5、校验返回结果 6、解析返回参数并比对签名值是否正确（可选）


@hms_api.route('/userlogin', methods=["POST"])
def userlogin():
    # 获取app发送来的用户信息
    baseUrl = "https://gss-cn.game.hicloud.com/gameservice/api/gbClientApi"
    method = "external.hms.gs.checkPlayerSign"
    appId = "appId"
    cpId = "cpId"
    ts = request.form.get("ts")
    playerId = request.form.get("playerId")
    playerLevel = request.form.get("playerLevel")
    playerSSign = request.form.get("playerSSign")

    privateKey = get_private_key()

    # 发送用户信息至华为服务器
    cp_server = GameCPService(baseUrl, method, appId, cpId, ts, playerId, playerLevel, playerSSign, privateKey)
    hms_response = cp_server.post_request()
    hms_response_dict = hms_response.json()
    if hms_response_dict.get('rtnCode') == 0:
        # 成功
        # 检查是否为新用户，如果是新用户则注册，如果是老用户则直接登录
        return 0
    elif hms_response_dict.get('rtnCode') == -1:
        # 失败
        pass
    elif hms_response_dict.get('rtnCode') == 1:
        # 接口鉴权失败
        pass
    elif hms_response_dict.get('rtnCode') == 3001:
        # 参数错误
        pass


# 服务端需要有一个专门用于签名的url
@hms_api.route('/payrecall', methods=["POST"])
def pay_recall():
    # 获取源串
    content = ""
    for i in request.form:
        if i != "sign" and i != "signType":
            content += "{}={}&".format(i, request.form.get(i))
        else:
            pass
    content = content.rstrip("&")
    logging.debug("content: {}".format(content))
    sign = request.form.get("sign")
    
    # 去除不参与验签的
    # 验签
    pub_key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIW1g+KAqqOeC1ypte8L3qTDk2nz6jUbM6o6Jg9obvivPnCAm/wZvV3jWbYWfOuO/wrFJygn/jZqf8cR1T1CQa8CAwEAAQ=="
    if verify_sign(pub_key, sign, content):
        logging.debug("result: {}".format("Success"))
        return jsonify({"result": 0})
    else:
        logging.debug("result: {}".format("Fail"))
        return jsonify({"result": 1})
