import deepsecurity
import sys, warnings

class ApiLoader:
    def __init__(self, host, api_key, version):
        self.host = host
        self.api_key = api_key
        self.version = version
        try:
            self.api_config = deepsecurity.Configuration()
            self.api_config.host = host
            self.api_config.api_key['api-secret-key'] = api_key
        except:
            raise TypeError("Invalid types: host - {} api_key - {}".format(type(host), type(api_key)))
    
    def request_computers(self):
        """Returns a list with all computers in the DS environment"""
        api_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(self.api_config))
        try:
            api_response = api_instance.list_computers(self.version, overrides=False)
        except ApiException as e:
            raise
        return api_response.computers

    
    def request_im_rules(self):
        """Returns a list with all integrity monitor rule"""
        api_instance = deepsecurity.IntegrityMonitoringRulesApi(deepsecurity.ApiClient(self.api_config))
    
        try:
	        api_response = api_instance.list_integrity_monitoring_rules(self.version)
        except Exception as e:
            raise

        return api_response.integrity_monitoring_rules

    def search_im_rules(self, criteria):
        max_items = None
        search_filter = deepsecurity.SearchFilter(max_items, criteria)

        im_api = deepsecurity.IntegrityMonitoringRulesApi(deepsecurity.ApiClient(self.api_config))

        try:
            api_response = im_api.search_integrity_monitoring_rules(self.version, search_filter=search_filter)
        except Exception as e:
            raise

        return api_response.integrity_monitoring_rules

    def request_ips_rules(self, condition=None, rule=None):
        api_instance = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(self.api_config))

        try:
	        api_response = api_instance.list_intrusion_prevention_rules(self.version)
        except Exception as e:
            raise
        
        return api_response.intrusion_prevention_rules

    def search_ips_rules(self, criteria):
        max_items = None
        search_filter = deepsecurity.SearchFilter(max_items, criteria)

        im_api = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(self.api_config))

        try:
            api_response = im_api.search_intrusion_prevention_rules(self.version, search_filter=search_filter)
        except Exception as e:
            raise

        return api_response.intrusion_prevention_rules



