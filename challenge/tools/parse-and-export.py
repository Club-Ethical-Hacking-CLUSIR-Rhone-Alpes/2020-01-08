import json
from elasticsearch import Elasticsearch
import datetime
import sys
import re

audit_mess_regex = r"Message:\s(?P<message>.*?)\[file.*?(\[msg\s\"(?P<reason>.*?)\"])?(\s\[data\s\"(?P<data>.*?)\"\])?(\s\[severity\s\"(?P<severity>.*?)\"\])?(\s\[ver\s\"(?P<version>.*?)\"\])?"

es = Elasticsearch( ['localhost:9200'],
    # sniff before doing anything
    sniff_on_start=True,
    # refresh nodes after a node fails to respond
    sniff_on_connection_fail=True,
    # and also every 60 seconds
    sniffer_timeout=60,
    http_auth=('admin', 'admin1234')
)

print('open json file')
f = open("../../logs/json_modsec_audit.logs/modsec_output/modsec_audit_2019-12-27_11-54-37.json", "r")
if f.mode == 'r':
    print('read content')
    contents = f.read()
    print('split content by line')
    contents = contents.split("\n")

    tmpJson = ""
    for i in range(len(contents)):
        tmpJson += contents[i]
        if(contents[i] == "}" and contents[i+1] == "{"):
            print("found json object")
            tmpJson = json.loads(tmpJson)

            tmpJson['@timestamp'] = datetime.datetime.strptime(tmpJson['transaction']['time'] , '%d/%b/%Y:%H:%M:%S +0100')
            tmpJson['@timestamp'] = "{}T{}".format(tmpJson['@timestamp'].date(), tmpJson['@timestamp'].time())

            try:
                if (tmpJson.has_key('audit_data') and tmpJson['audit_data'].has_key('messages')):
                    tmpJson['audit_data']['messages_raw'] = []
                    tmpJson['audit_data']['messages_parsed'] = []
                    for j in range(len(tmpJson['audit_data']['messages'])):

                        matches = re.search(audit_mess_regex, tmpJson['audit_data']['messages'][j], re.MULTILINE)
                        if matches:
                            print("message = {}".format(matches.group('message')))
                            tmpJson['audit_data']['messages_parsed'].append({
                                'message': matches.group('message'),
                                'reason': matches.group('reason'),
                                'data': matches.group('data'),
                                'severity': matches.group('severity')
                            })
                            tmpJson['audit_data']['messages_raw'].append(matches.group('message'))
                res = es.index(index="web-logs", doc_type="doc", body=tmpJson)
                print(res)
            except:
                print("Unexpected error:", sys.exc_info()[0])
            tmpJson = ""
