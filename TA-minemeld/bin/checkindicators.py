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
import re
import ipaddress
import requests.exceptions

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six
from splunklib.six.moves import range

@Configuration()
class CheckIndicatorsCommand(StreamingCommand):
    input_name = Option(doc=''' **Syntax:** **input_name=***<inputname>*
    **Description:** Name of the input that will be used to find feed url and credentials''',
    require=True)
    indicator_field = Option(doc=''' **Syntax:** **indicator_field=***<indicatorfield>*
    **Description:** Name of the field that contains the indicator''',
    require=True, default="indicator", validate=validators.Fieldname())

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

    def indicatorInIndicators(self, indicator, indicators):
        for i in indicators:
            if re.match(r"(\d+\.){3}\d+\/\d+", i):
                if ipaddress.IPv4Address(indicator) in ipaddress.IPv4Network(i):
                    return True
            elif indicator == i:
                return True
        return False

    def stream(self,records):
        indicators = self.get_incicators_only("minemeldfeeds", self.input_name)
        for record in records:
            if None != record.get('indicator'):
                if self.indicatorInIndicators(record.get(self.indicator_field), indicators):
                    record['in_minemeld'] = 1
                else:
                    record['in_minemeld'] = 0
            else:
                record['in_minemeld'] = ""
            yield record

dispatch(CheckIndicatorsCommand, sys.argv, sys.stdin, sys.stdout, __name__)


