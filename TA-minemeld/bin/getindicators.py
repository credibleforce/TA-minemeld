#!/usr/bin/env python
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
import requests.exceptions

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
from splunklib import six
from splunklib.six.moves import range


@Configuration()
class GetIndicatorsCommand(GeneratingCommand):

    input_name = Option(doc=''' **Syntax:** **input_name=***<inputname>*
    **Description:** Name of the input that will be used to find feed url and credentials''',
    require=True)

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

    def get_feed(self, name, splunk_source):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        query = json.dumps({})
        if splunk_source != "*":
            query = json.dumps({"splunk_source": splunk_source})
        return collection.data.query(query=query)

    def get_feed_entries(self, name, splunk_source, start):
        collection_name = name
        collection = self.service.kvstore[collection_name]
        query = json.dumps({})
        if splunk_source != "*":
            query = json.dumps({"splunk_source": splunk_source})
        return self.normalized(name, collection.data.query(query=query), start)

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

    def generate(self):
        storage_passwords=self.service.storage_passwords
	
        url = {'server_uri': "{0}://{1}:{2}".format(self.service.scheme,self.service.host,self.service.port),'session_key': self.service.token}
        #yield url


        ######### RETURN MINEMELD KVSTORE ###########
        indicators = self.get_feed("minemeldfeeds", self.input_name)
        i = 0
        for indicator in indicators:
            yield {'_serial': i, '_time': time.time(), '_key': indicator['_key'],'_raw': six.text_type(json.dumps(indicator)) }
            #yield { '_key': indicator['_key'] }
            i = i + 1
        
        ######### RETURN MINEMELD KVSTORE #########

        ######### UPDATE MINEMELD KVSTORE #########
        # try:
        #    indicator_timeout = int(helper.get_arg('indicator_timeout')) * 3600
        # except ValueError:
        #     # If this isn't set, timeout indicators immediately.
        #     indicator_timeout = 0

        # name="minemeldfeeds"
        # collection_name = name
        # collection = self.service.kvstore[collection_name]

        # rms = []
        # rms.append("601356379cea4b8fa033e0ad") #1.1.1.0/27
        
        # query = {'$or': list({'_key': x} for x in rms)}
        # r = collection.data.delete()

        # yield r

        # indicator_timeout = 0
        # start = time.time()
        # stats = {'input_name': 'test'}
        # kvs_entries = self.pull_from_kvstore(name)
        # stats['previous_indicators'] = len(kvs_entries)

        # mmf_entries = []
        # try:
        #     mmf_entries = self.get_feed_entries("minemeldfeeds", start)
        # except requests.exceptions.HTTPError as e:
        #     stats['error'] = str(e)
        # stats['feed_indicators'] = len(mmf_entries)

        # # Merge the two together, and determine which indicators should be expired.
        # rm_entries, retained_indicators = self.merge_entries(
        #     mmf_entries, kvs_entries, start, indicator_timeout, stats)
        # stats['expired_indicators'] = len(rm_entries)
        # stats['indicators'] = len(mmf_entries) + retained_indicators

        # # Save new/updated indicators to the kvstore.
        # self.save_to_kvstore(name, mmf_entries, stats)

        # # Delete the expired indicators.
        # self.remove_from_kvstore(name, rm_entries, stats)
        ######### UPDATE MINEMELD KVSTORE #########


        ######### OTHER EXAMPLES ##############
        #for credential in storage_passwords:
            #    usercreds = {'username':credential.content.get('username'),'password':credential.content.get('clear_password')}
            #    yield usercreds
        #print(self.service.storage_passwords)
            #text = self.text
            #self.logger.debug("Generating %d events with text %s" % (self.count, self.text))
            #for i in range(1, self.count + 1):
            #    yield {'_serial': i, '_time': time.time(), '_raw': six.text_type(i) + '. ' + text}
        ######### OTHER EXAMPLES ##############

dispatch(GetIndicatorsCommand, sys.argv, sys.stdin, sys.stdout, __name__)

