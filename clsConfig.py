import configparser

class Configuration:
    def __init__(self,configf=None):
        self.configfile=configf
        self.config=configparser.RawConfigParser()

    def prepConfig(self):
        try: 
            '''configPath=r'config.cfg'''
            self.config.read(self.configfile)

        except ValueError:
            return False
        except Exception as e:
         print('Unknown Config Preparation Exception '+str(e))

    def getParam(self,cparam,cvalue):
        try:
            param=self.config.get(cparam,cvalue)

            return param
        except ValueError:
            return False
        except Exception as e:
         print('Unknown Get Parameter Exception '+str(e))
