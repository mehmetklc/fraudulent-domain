import requests
import syslog
import argparse

class FraudulentDomain(object):

    def __init__(self, base_url, vendor, product):

        self.__base_url = base_url
        self.__cef_vendor = vendor
        self.__cef_product = product
        self.__cef_version = "101"
        self.__cef_class_id = "100"
        self.__cef_name = "Fraudulent Domain"
        self.__cef_severity = "10"

    def run(self):
        try:
            url = self.__base_url
            response = requests.get(url, verify=False)

            if response.content != None:
                fd_feed_list = response.content.split('\n')

                for fraudulent_domain in fd_feed_list:
                    if fraudulent_domain and fraudulent_domain[0] != '#':
                        syslog.openlog('FraudulentDomain', 0, syslog.LOG_INFO)
                        syslog.syslog('CEF:0|{0}|{1}|{2}|{3}|{4}|{5}|request={6}'.format(self.__cef_vendor,self.__cef_product,self.__cef_version,self.__cef_class_id,self.__cef_name,self.__cef_severity,fraudulent_domain))

            else:
                print "Response content of of the service is empty!!!"

        except IndexError as ie:
            print ie.message
        except Exception as e:
            print e.message


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Fraudulent Domain Text Format URL", required=True)
    parser.add_argument("-v", "--vendor", help="Fraudulent Domain Provider", required=True)
    parser.add_argument("-p", "--product", help="Fraudulent Domain Service", required=True)

    args = parser.parse_args()

    f_domain = FraudulentDomain(args.url,args.vendor,args.product)
    f_domain.run()
