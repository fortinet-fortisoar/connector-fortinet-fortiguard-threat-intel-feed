""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import ast
import io
import gzip
import json
import arrow
import os
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from .utils import create_batch_records

logger = get_logger('fortinet-fortiguard-threat-intel-feed')
BATCH_SIZE = 2000

class FortiguardThreatIntelligence(object):
    def __init__(self, config, *args, **kwargs):
        url = config.get('server_url')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url.strip('/'))
        else:
            self.url = url.strip('/') + '/'
        self.ssl_verify = config.get('verify_ssl')
        self.token= config.get('token')

    def validate_config(self):
        url = self.url + 'v1/fgd/psirt/detail?id=1'
        headers={"Token": self.token}
        response=requests.get(url, headers=headers)
        # since this is a dummy id, it would result in 404 which would still be ok since creds and url is validated to be correct
        if response.ok or response.status_code == 404:
            return True
        else:
            return False

def ingest_feeds(config, params, **kwargs):
    # TODO: pull from config and params
    token = config.get("token")
    if not token:
        raise ConnectionError("An Access Token is required to download the Threat Intelligence Feeds. Generate your access token from the Fortinet Developer Network Site Toolkit subscription and add it under the connector configuration.")
    
    server_url = config.get('server_url')
    if not server_url.startswith('https://') and not server_url.startswith('http://'):
        server_url = 'https://{0}/'.format(server_url.strip('/'))
    else:
        server_url = server_url.strip('/') + '/'
    cc = params.get("cc", "all")
    # empty string should also be replaced
    if not cc.strip():
        cc = "all"
    api_url = server_url + "v1/cti/feed/stix2?cc=" + cc
    date = params.get("date")
    if date:
        api_url = api_url + "&date=" + date
    modified_after = params.get("modified_after")
    create_pb_id = params.get("create_pb_id")
    parent_wf = kwargs.get('env', {}).get('wf_id')
    parent_step = kwargs.get('env', {}).get('step_id')

    # Request header insertion
    headers = {"Accept": "application/json",
               "Token": token}
    # API call
    response = requests.get(api_url, headers=headers)
    # Downloading feed data
    try:
        feed_url = ast.literal_eval(response.text)[0]['data']
    except:
        message = 'No download retreived from Fortiguard server. Response from server: %s', response.text
        # logger.error(message)
        raise ConnectorError(message)
    # Decompress feed data
    feed_data = requests.get(feed_url)
    compressed_file = io.BytesIO(feed_data.content)
    feed_text = gzip.GzipFile(fileobj=compressed_file)
    # Write feed data
    # TODO: relative to the current file
    filename_stix = "/tmp/" + cc + "." + datetime.now().strftime('%Y%m%d%H%M%S') + ".json"
    file = open(filename_stix, "w")
    file.write(feed_text.read().decode("utf-8"))
    file.close()

    with open(filename_stix) as temp_read:
        data_json = json.load(temp_read)
        
    os.remove(filename_stix)
    # check if the feed was already ingested
    if modified_after:
        # first object is identity type
        # TODO: test this to ensure first object is always identity
        identity_object = data_json["objects"][0]
        if identity_object["type"] == "identity" and (arrow.get(identity_object["modified"]).int_timestamp < modified_after):
            return {"message": "Feed not refreshed since the last pull"}
    
    logger.info("Creating feed records...")

    indicators = data_json["objects"]
    try:
        filtered_indicators = [indicator for indicator in indicators if indicator["type"] == "indicator"]
        # and arrow.get(indicator["modified"]).int_timestamp >= modified_after]: TODO: check if this is helpful
        # dedup 
        seen = set()
        deduped_indicators = [x for x in filtered_indicators if [x["pattern"] not in seen, seen.add(x["pattern"])][0]]
        for start_index in range(0, len(deduped_indicators), BATCH_SIZE):
            create_batch_records(deduped_indicators[start_index: start_index + BATCH_SIZE], create_pb_id, parent_wf, parent_step)
        return {"message": "Succesfully triggered playbooks for creating feed records"}
    except Exception as e:
        logger.exception("Import Failed")
        raise ConnectorError('Ingestion Failed with error: ' + str(e))            
    
    return {"message": "Successfully triggered record creation playbooks"}

def _check_health(config):
    try:
        etp = FortiguardThreatIntelligence(config)
        is_health_check_success = etp.validate_config()
    except Exception as err:
        logger.exception('health check failed')
        raise ConnectorError('Error: {0}'.format(err))
    if not is_health_check_success:
        raise ConnectorError('Invalid URL or token')
    return is_health_check_success


operations = {
    'ingest_feeds': ingest_feeds,
    'check_health': _check_health,
}
