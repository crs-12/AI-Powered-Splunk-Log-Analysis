import os
from dotenv import load_dotenv

import splunklib.client as client
import splunklib.results as results

load_dotenv()


def connect_splunk():

    service = client.connect(
        host="localhost",
        port=8089,
        username=os.getenv("SPLUNK_USER"),
        password=os.getenv("SPLUNK_PASS")
    )

    return service


def get_splunk_alerts():

    query = r'''
    search index=* source="ssh_logs_1000.txt"
    | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
    | rex "for (?<username>\w+)"
    | eval status=if(match(_raw,"Accepted"),"Accepted","Failed")
    | stats count by src_ip username status
    | sort - count
    | head 20
    '''

    return run_splunk_query(query)


def run_splunk_query(query):

    service = connect_splunk()

    if not query.strip().startswith("search"):
        query = "search " + query

    job = service.jobs.create(query)

    while not job.is_done():
        pass

    reader = results.ResultsReader(job.results())

    data = []

    for item in reader:
        if isinstance(item, dict):
            data.append(item)

    return data