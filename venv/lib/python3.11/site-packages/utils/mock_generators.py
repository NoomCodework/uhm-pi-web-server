import pickle
import base64
from copy import deepcopy

class Monitor:

    RUN_MONITORED_TEMPLATE = "Results id: {results_id}\nMethod runned: {f_qualname}\n*args: {args}\n**kwargs: {kwargs}"

    def _purge_monitors(self):
        self.monitored_results = {}
    
    def _add_to_readme(self, txt):

        self.readme += "\n---------------------------------------------\n{}".format(txt)

    def get_results_identifier(self,):

        assert self._results_identifier is not None, "There is a big problem with results identifier strategy... Sad... Very sad!"

        a = deepcopy(self._results_identifier)

        return a

    def __init__(self):
        
        self.readme = ""
        self._purge_monitors()

    def save_mock_file(self, file_path):

        with open(file_path, "wb") as fp:

            pickle.dump(deepcopy(self.monitored_results), fp)

    def register_results_and_return(self, func, results_transf_func=None):
        def _f(*args, **kwargs):

            results = results_transf_func(func(*args, **kwargs)) if results_transf_func is not None else func(*args, **kwargs)

            results_id = self.get_results_identifier()

            if not func.__qualname__ in self.monitored_results:
                self.monitored_results[func.__qualname__] = {results_id: results}
            else:
                self.monitored_results[func.__qualname__][results_id] = results

            return results

        return _f

    def run_monitored(self, func, results_identifier, args_transf_func=None, *args, **kwargs):

        self._results_identifier = results_identifier

        if args_transf_func is not None:
            args_transf, kwargs_transf = args_transf_func(deepcopy(args), deepcopy(kwargs))
        else:
            args_transf, kwargs_transf = args, kwargs

        to_readme = self.RUN_MONITORED_TEMPLATE.format(
            results_id=self.get_results_identifier(),
            f_qualname=func.__qualname__,
            args=args_transf,
            kwargs=kwargs_transf
        )

        results = func(*args, **kwargs)

        self._add_to_readme(to_readme)

        self._results_identifier = None

        return results