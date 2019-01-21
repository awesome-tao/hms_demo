
class Config(object):
    SECRET_KEY = "123456"


class DevelopmentConfig(Config):
    pass


config = {
    "default": DevelopmentConfig
}