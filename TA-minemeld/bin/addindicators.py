#!/usr/bin/env python3
# coding=utf-8
#
# Copyright © 2011-2015 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# example cmd exec (note: session values not include on cli)
# bin/splunk cmd python bin/generatetext.py __EXECUTE__ count=1 text=test < /dev/null

from __future__ import absolute_import, division, print_function, unicode_literals
import app
import os,sys
import time
import base64
import functools
import json
import ipaddress
import re
import requests.exceptions
from requests import ConnectionError

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six
from splunklib.six.moves import range
import pprint

@Configuration()
class AddIndicatorsCommand(StreamingCommand):

    input_name = Option(doc=''' **Syntax:** **input_name=***<inputname>*
    **Description:** Name of the input that will be used to find feed url and credentials''',
    require=True)
    indicator_field = Option(doc=''' **Syntax:** **indicator_field=***<indicatorfield>*
    **Description:** Name of the field that contains the indicator''',
    require=True, default="indicator", validate=validators.Fieldname())
    type_field = Option(doc=''' **Syntax:** **type_field=***<typefield>*
    **Description:** The type of indicator (i.e. IPv4, URL)''',
    require=True,default="type", validate=validators.Fieldname())
    comment_field = Option(doc=''' **Syntax:** **comment_field=***<commentfield>*
    **Description:** Name of the field that contains the indicator comment''',
    require=True,default="comment", validate=validators.Fieldname())
    confidence_field = Option(doc=''' **Syntax:** **confidence_field=***<confiedencefield>*
    **Description:** Name of the field that contains the indicator confidence''',
    require=False,default="confidence", validate=validators.Fieldname())
    share_level_field = Option(doc=''' **Syntax:** **share_level_field=***<sharelevelfield>*
    **Description:** Name of the field that contains the indicator share level''',
    require=True,default="share_level", validate=validators.Fieldname())

    def pull_from_kvstore(self,name):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        ans = {}
        for v in collection.data.query():
            ans[v['indicator']] = {
                '_key': v['_key'],
                'is_present': False,
                'splunk_last_seen': v.get('splunk_last_seen', 0.0)
                }
        return ans

    def get_incicators_only(self, name,splunk_source):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        query = json.dumps({})
        if splunk_source != "*":
            query = json.dumps({"splunk_source": splunk_source})
        indicators = []
        for indicator in collection.data.query(query=query):
            indicators.append(indicator['indicator'])
        return indicators

    def get_feed(self, name):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        return collection.data.query()

    def get_feed_entries(self, name, start):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        return self.normalized(name, collection.data.query(), start)

    def merge_entries(self, mmf_entries, kvs_entries, start, indicator_timeout, stats):
        """
        Merges the current indicators with previous, determining which should
        be expired.
        """
        rm_entries = []
        retained_indicators = 0

        for mmfe in mmf_entries:
            kvse = kvs_entries.get(mmfe['indicator'])
            if kvse is not None:
                kvse['is_present'] = True
                mmfe['_key'] = kvse['_key']

        for info in iter(kvs_entries.values()):
            if info['is_present']:
                pass
            elif info['splunk_last_seen'] + indicator_timeout < start:
                rm_entries.append(info['_key'])
            else:
                retained_indicators += 1

        return rm_entries, retained_indicators

    def save_to_kvstore(self, name, entries, stats):
        """Saves all normalized entries as `name` events."""
        collection_name = name
        collection = self.service.kvstore[collection_name]
        for entry in entries:
            collection.data.insert(json.dumps(entry))

    def remove_from_kvstore(self, name, rm_entries, stats):
        """Removes the specified entries from the kvstore."""
        if not rm_entries:
            return

        collection_name = name
        collection = self.service.kvstore[collection_name]
        
        for i in range(0, len(rm_entries), 500):
            rms = rm_entries[i:i+500]
            query = {'$or': list({'_key': x} for x in rms)}
            collection.data.delete(query)


    def normalized(self, name, feed_entries, start):
        """Returns a list of normalized kvstore entries."""
        data = []
        for feed_entry in feed_entries:
            if 'indicator' not in feed_entry or 'value' not in feed_entry:
                continue

            # Make the entry dict.
            entry = feed_entry.copy()
            entry['splunk_source'] = name
            entry['splunk_last_seen'] = start

            data.append(entry)

        return data

    def indicatorInIndicators(self, indicator, indicators):
        for i in indicators:
            if re.match(r"(\d+\.){3}\d+\/\d+", i):
                if ipaddress.IPv4Address(indicator) in ipaddress.IPv4Network(i):
                    return True
            elif indicator == i:
                return True
        return False
        

    def stream(self,records):
        self.logger.logging_level = 'DEBUG'

        self.logger.debug('addindicators input_name={0} indicator_field={1} comment_field={2} confidence_field={3}'.format(self.input_name, self.indicator_field, self.comment_field, self.confidence_field))
        
        ip_indicators = []
        
        cred_path = 'storage/passwords/__REST_CREDENTIAL__#TA-minemeld#data%2Finputs%2Fpalo_minemeld:' + self.input_name + '``splunk_cred_sep``1:/'
        input_path = '/servicesNS/nobody/TA-minemeld/data/inputs/palo_minemeld/' + self.input_name  + '/'
        feed_server = None
        feed_input_name = None
        feed_username = None
        feed_password = None
        feed_url = None
        feed_ttl = None

        inputs = self.service.inputs
        for input_object in inputs:
            if input_object.path == input_path:
                feed_server = input_object.content.get('feed_server')
                feed_input_name = input_object.content.get('feed_input_name')
                feed_url = "{0}/config/data/{1}_indicators/append?h={1}&t=localdb".format(feed_server,feed_input_name)
                feed_username = input_object.content.get('feed_username')
                feed_ttl = input_object.content.get('indicator_timeout')
                break
        
        storage_passwords=self.service.storage_passwords
        for credential in storage_passwords:
            if credential.path == cred_path:
                feed_password = json.loads(credential.clear_password)['feed_password']
                break
        
        # get indicators by input name (splunk_source)
        indicators = self.get_incicators_only("minemeldfeeds", self.input_name)

        for record in records:
            if None != record.get(self.indicator_field):
                # check for ipv4 in network or in indicators generally
                if not self.indicatorInIndicators(record.get(self.indicator_field), indicators):
                    if None == record.get(self.comment_field):
                        comment = "Added by splunk"
                    else:
                        comment = record.get(self.comment_field)

                    if None == record.get(self.confidence_field):
                        confidence = " "
                    else:
                        confidence = record.get(self.comment_field)
                    
                    ip_indicators.append({
                        'indicator': record.get(self.indicator_field), 
                        'type': record.get(self.type_field), 
                        'ttl': int(feed_ttl), 
                        'share_level': record.get(self.share_level_field),
                        'source_name': self.input_name,
                        'comment': record.get(self.comment_field)
                    })
                    record['minemeld_action'] = "add"
                else:
                    record['minemeld_action'] = "none"
            else:
                record['minemeld_action'] = "none"
                
            yield record
        
        # pull the url and credentials for the feed
        self.logger.info("Found {0} new indicators".format(len(ip_indicators)))
        if len(ip_indicators) > 0:
            if None != feed_username and None != feed_password and None != feed_url:
                basic_auth_data = base64.b64encode(":".join([feed_username, feed_password]).encode())
                headers = {"Authorization": "Basic {0}".format(basic_auth_data.decode()), "Content-Type": "application/json"}
                data = ip_indicators
                self.logger.info(json.dumps(data,indent=4))
                
                response = requests.post(url=feed_url, json=data, headers=headers, verify=False)
                if response.status_code != 200:
                    self.logger.error("Add to minemeld failed: Minemeld update failed: {0}".format(response.status_code))
                else:
                    self.logger.info("Minemeld success response: {0}".format(response.status_code))
            else:
                self.logger.error("Add to minemeld failed: Unable to locate input: {0}".format(self.input_name))
                raise Exception("Add to minemeld failed: Unable to locate input: {0}".format(self.input_name))
        else:
            self.logger.info("No new indicators found. No action taken")

dispatch(AddIndicatorsCommand, sys.argv, sys.stdin, sys.stdout, __name__)


