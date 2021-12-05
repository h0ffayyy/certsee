import requests


# build censys object
class Censys:
    def __init__(self):
        pass

    # query API by certificate serial
    def query_serial(self):

        certificate_serial="13955790621440138352670111411558754022"

        request_body = {"query":f"parsed.serial_number: {certificate_serial}", 
                        "page": 1, 
                        "flatten": False}
        headers = {"Content-Type":"application/json"}

        res = requests.post(url="https://search.censys.io/api/v1/search/certificates", 
                            json=request_body,
                            auth=(api_id, api_secret))

        print(res.content)