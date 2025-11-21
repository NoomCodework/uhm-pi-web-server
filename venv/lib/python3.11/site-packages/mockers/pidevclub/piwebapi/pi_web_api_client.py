from osisoft.pidevclub.piwebapi.pi_web_api_client import PIWebApiClient
from utils.mock_generators import Monitor
from utils.os_utils import make_dir_if_does_not_exist
import pickle
import os

""" def _getatrr(obj, attr):

    attr_split = attr.split('')
    if len(attr_split) > 1:

        return _getatrr(_getattr(getattr(obj, attr_split[0]), attr_split[]))
 """

class PIWebApiClientMonitored(PIWebApiClient):

    def _get_monitor_folderpath(self, id):

        filename = "osisoft.pidevclub.piwebapi.pi_web_api_client.PIWebApiClient_{}".format(id)
        
        if self._tests_mocks_path is None:

            raise Exception("There is not a tests' mocks' path defined. Set it using the method `set_tests_mocks_path(...)` from this object.")

        filepath = os.path.join(self._tests_mocks_path, filename)

        return filepath

    def set_tests_mocks_path(self, path):

        self._tests_mocks_path = path

    def __init__(self, baseUrl, useKerberos=True, username=None, password=None, verifySsl=True, useNtlm=False):

        self.monitor = Monitor()

        self._tests_mocks_path = None

        super().__init__(
            baseUrl,
            useKerberos,
            username,
            password,
            verifySsl,
            useNtlm
        )

    def set_thing_to_mock(self, t, f=None):

        return self.monitor.register_results_and_return(t, f)

    def make_mock(self, func, results_identifier, args_transf_func=None, *args, **kwargs):

        return self.monitor.run_monitored(
            func, 
            results_identifier, 
            args_transf_func, 
            *args, 
            **kwargs
        )

    def save_monitor(self, id):

        case = self._get_monitor_folderpath(id)

        make_dir_if_does_not_exist(case)

        with open(os.path.join(case, 'mock'), 'wb') as fp:

            pickle.dump(self.monitor, fp)

        with open(os.path.join(case, 'README.md'), 'w+') as fp:

            fp.write(self.monitor.readme)

    def load_monitor(self, id):

        case = self._get_monitor_folderpath(id)

        with open(os.path.join(case, 'mock'), 'rb') as fp:

            self.monitor = pickle.load(fp)

    def _mock(self, t, results_id):

        def _f(*args, **kwargs):

            results = self.monitor.monitored_results[t.__qualname__][results_id]

            return results

        return _f

    def mock_responses(self, t, results_id):

        return self._mock(t, results_id)



