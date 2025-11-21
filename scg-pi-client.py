from typing import Optional
import pandas as pd
from osisoft.pidevclub.piwebapi.pi_web_api_client import PIWebApiClient
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PIWebAPI:
    def __init__(self, api_server: str, user: str, pwd: str, pi_server: str):
        self.client = PIWebApiClient(api_server, False, user, pwd, False, True)
        self.pi_server = pi_server

    def convertPathtoWebIds(self, path: list):
        paths = ["pi:\\\\" + self.pi_server +
                 "\\" + x for i, x in enumerate(path)]
        webIds = self.client.data.convert_paths_to_web_ids(paths)
        return webIds

    def convertAverageDicttoDataFrame(self, data, tag_list: list):
        print('tag_list before insert:', tag_list)
        print('data:', data)
        tag_list.insert(0, "timestamp")
        i = 0
        lst_main = list()

        while i < len(data.items[0].items):
            lst_sub = list()
            j = 0
            while j < len(tag_list):
                if j == 0:
                    lst_sub.append(data.items[0].items[i].value.timestamp)
                else:
                    lst_sub.append(data.items[j - 1].items[i].value.value)
                j = j + 1
            lst_main.append(lst_sub)
            i = i + 1

        df = pd.DataFrame(lst_main, columns=tag_list)
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], format="%Y-%m-%dT%H:%M:%S.%fZ"
        ) + pd.to_timedelta("07:00:00")
        return df

    def getAverageValue(
        self,
        tag_list: list,
        start_time: str,
        end_time: str,
        cal_basis: str,
        summary_type: list,
        summary_duration: Optional[str] = None,
        filter_expression: Optional[str] = None,
    ):
        webIds = self.convertPathtoWebIds(tag_list)
        # if summary_duration is None:
        #    df = self.client.streamSet.get_summaries_ad_hoc(web_id=webIds,start_time=start_time,end_time=end_time,calculation_basis=cal_basis,summary_type=summary_type,filter_expression=filter_expression)
        # else:
        df = self.client.streamSet.get_summaries_ad_hoc(
            web_id=webIds,
            start_time=start_time,
            end_time=end_time,
            calculation_basis=cal_basis,
            summary_type=summary_type,
            summary_duration=summary_duration,
        )
        df = self.convertAverageDicttoDataFrame(df, tag_list)
        return df
    
api_server = 'http://localhost:8000'
user = 'noom'
pwd = 'password123'
pi_server = 'uhm-test'
webapi = PIWebAPI(api_server, user, pwd, pi_server)
sensor_ids = ['uhm-test\\sinusoid', 'uhm-test\\random']
start = '2024-01-01T00:00:00Z'
end = '2024-01-02T00:00:00Z'
cal_basis = 'timeweighted'
cal_type = ['average']
interval = '1h'
try:
    df_pi = webapi.getAverageValue(sensor_ids, start, end, cal_basis, cal_type, interval)
    print('df_pi:', df_pi)
except Exception as e:
    print(
        f"Batch API call failed for chunk: {sensor_ids}\nRetrying individually...")

    frames = []
    for tag in sensor_ids:
        try:
            single_df = webapi.getAverageValue(
                [tag], start, end, cal_basis, cal_type, interval)
            if single_df is not None:
                frames.append(single_df)
        except Exception as inner_e:
            print(f"Failed to retrieve tag: {tag} — {inner_e}")