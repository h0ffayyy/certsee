import requests

class Censys:
    """Contains information about results from a Censys.io search

    Attributes:
        fingerprints - a list of sha256 fingerprints for matching certificates
    
    """
    def __init__(self, domain, timeframe):
        self.domain_name = domain
        self.fingerprints = self.query_serial(self.domain_name)
        self.lookback = timeframe

    # TODO: only search for certificates within lookback
    # parsed.validity.start: [2021-12-03 to 2021-12-05]
    # need to get current date, subtract lookback time

    def query_serial(self, domain):
        """Query Censys.io for certificates that match a given domain name

        Params:
            self - N/A

        """

        domain_name=""
        certificate_fingerprints = []

        request_body = {"query":f"parsed.names: {domain_name}", 
                        "page": 1, 
                        "flatten": False}
        headers = {"Content-Type":"application/json"}

        try:
            res = requests.post(url="https://search.censys.io/api/v1/search/certificates", 
                                json=request_body,
                                auth=(api_id, api_secret))

            # add fingerprints to list
            results = res.json()['results']
            print(results)
            for result in results:
                certificate_fingerprints.append(result['parsed']['fingerprint_sha256'])

            return certificate_fingerprints
        except Exception as e:
            print(e)
            
