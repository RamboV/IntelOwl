import logging

from api_app.analyzers_manager import classes
from api_app.mixins import IPQualityScoreMixin
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class IPQSUrlScan(classes.ObservableAnalyzer, IPQualityScoreMixin):
    """
    Scan a URL using IPQualityScore service.
    """

    scan_url = "/malware/scan/"
    lookup_url = "/malware/lookup/"
    postback_url = "/postback/"

    def run(self):

        # lookup check for url results into ipqs database
        lookup_result = self._make_request(
            endpoint=self.lookup_url,
            method="POST",
            _api_key=self._ipqs_api_key,
            data={"url": self.observable_name},
        )
        if lookup_result.get("status", False) == "cached":
            lookup_result.pop("update_url", None)
            return lookup_result

        # sending url for scan
        scan_result = self._make_request(
            endpoint=self.scan_url,
            method="POST",
            _api_key=self._ipqs_api_key,
            data={"url": self.observable_name},
        )
        # waiting for results for with request id of scanned results
        result = self._poll_for_report(
            endpoint=self.postback_url,
            _api_key=self._ipqs_api_key,
            request_id=scan_result.get("request_id"),
        )
        result.pop("update_url", None)
        return result

    @classmethod
    def _monkeypatch(cls):
        # Response for lookup endpoint (non-cached case)
        lookup_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "status": "not_cached",
            "request_id": "dxwrE9RhS3",
        }

        # Response for scan endpoint
        scan_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "request_id": "dxwrE9RhS3",
        }

        # Final response from poll_for_report
        final_response = {
            "file_name": "www.google.com",
            "success": True,
            "message": "Success",
            "file_hash": "86cc9b097d5ea4ec64a086634ef0f57b864770ccd1129ee1d2448093950e80cd",
            "type": "scan",
            "detected": False,
            "detected_scans": 0,
            "total_scans": 0,
            "status": "finished",
            "result": [""],
            "file_size": 272728,
            "file_type": "text/html",
            "sha1": "379066b095304b84a0cc53888cda558ef483a4dd",
            "md5": "4eb7c45715293e6effd84f4894cff654",
            "request_id": "dxwrE9RhS3",
        }

        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    side_effect=[
                        MockUpResponse(lookup_response, 200),
                        MockUpResponse(scan_response, 200),
                    ],
                ),
            ),
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(final_response, 200),
                ),
            ),
        ]
        return super()._monkeypatch(patches=patches)
