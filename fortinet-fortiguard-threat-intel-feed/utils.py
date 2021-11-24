from integrations.crudhub import make_request
from connectors.core.connector import get_logger

logger = get_logger('fortinet-fortiguard-threat-intelligence')


def create_batch_records(records, create_pb_id, parent_wf, parent_step):
    try:
        url = "/api/triggers/1/notrigger/" + create_pb_id
        method = "POST"
        payload = {
            "_eval_input_params_from_env": True,
            "env": {
                "ingestedData": records
            }
        }
        if parent_wf:
            payload['parent_wf'] = parent_wf
        if parent_step:
            payload['parent_id'] = parent_step
        make_request(url, method, body=payload)
    except Exception as e:
        logger.error("Failed to insert a batch of feeds with error: " + str(e))    

def sample_feeds():
    return [
            {
                "created": "2021-08-19T07:09:16.546999+00:00",
                "created_by_ref": "identity--77138c7e-d23e-4966-922c-578c5793e82c",
                "id": "indicator--8f21728d-6206-4cb7-9248-fb05c4ecfc9a",
                "indicator_types": [
                    "domain-watchlist"
                ],
                "modified": "2021-08-19T07:09:16.546999+00:00",
                "name": "Malicious domains",
                "pattern": "[url:value = 'trumphujtebevrot.bit']",
                "pattern_type": "stix",
                "spec_version": "2.1",
                "type": "indicator",
                "valid_from": "2021-08-19T00:00:00",
                "valid_until": "2021-08-24T00:00:00"
            },
            {
                "created": "2021-08-19T07:09:16.546999+00:00",
                "created_by_ref": "identity--77138c7e-d23e-4966-922c-578c5793e82c",
                "id": "indicator--bef17ec9-ac57-482e-9b50-32023c50a728",
                "indicator_types": [
                    "url-watchlist"
                ],
                "modified": "2021-08-19T07:09:16.546999+00:00",
                "name": "Malicious URLs",
                "pattern": "[url:value = 'http://dood.to/d/8djq6xhrqx31']",
                "pattern_type": "stix",
                "spec_version": "2.1",
                "type": "indicator",
                "valid_from": "2021-08-19T00:00:00",
                "valid_until": "2021-08-24T00:00:00"
            },
            {
                "created": "2021-08-19T07:06:55.546999+00:00",
                "id": "indicator--6f159a90-752e-4e6b-bebb-28e03c62c175",
                "indicator_types": [
                    "malicious-activity"
                ],
                "modified": "2021-08-19T07:06:55.546999+00:00",
                "name": "ZeroAccess",
                "pattern": "[network-traffic:src_port = 16464 AND network-traffic:src_ref.value = '24.45.106.57']",
                "pattern_type": "stix",
                "spec_version": "2.1",
                "type": "indicator",
                "valid_from": "2021-08-19T00:00:00",
                "valid_until": "2021-08-24T00:00:00"
            }

        ]