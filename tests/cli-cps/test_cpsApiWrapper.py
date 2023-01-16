import pytest

from bin.cpsApiWrapper import (
    cps as CPSAPIWrapper,
)

CHANGE_ID = "test_change"
CONTRACT_ID = "test_contract"
DATA = "test_data"
ENDPOINT = "/test_endpoint"
ENROLLMENT_ID = "test_enrollment"


class TestCPS:
    access_hostname = "www.example.com"
    account_switch_key = ""
    cps = CPSAPIWrapper(access_hostname, account_switch_key)
    cps_with_key = CPSAPIWrapper(access_hostname, "key")

    def test_constructor(self):
        assert self.cps.access_hostname == self.access_hostname
        assert self.cps.account_switch_key == self.account_switch_key

        assert self.cps_with_key.access_hostname == self.access_hostname
        assert self.cps_with_key.account_switch_key == "&accountSwitchKey=key"

    @pytest.mark.parametrize("session", [("GET", "/contract-api/v1/contracts/identifiers", 200)], indirect=True)
    def test_get_contracts(self, session):
        resp = self.cps.get_contracts(session)
        resp_with_switch_key = self.cps_with_key.get_contracts(session)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/contract-api/v1/contracts/identifiers?depth=TOP"

        assert resp_with_switch_key.status_code == 200
        assert resp_with_switch_key.request.url == "https://www.example.com/contract-api/v1/contracts/identifiers" \
                                                   "?depth=TOP&accountSwitchKey=key"

    @pytest.mark.parametrize("session", [("POST", "https://www.example.com/cps/v2/enrollments", 200)], indirect=True)
    def test_create_enrollment(self, session):
        resp = self.cps.create_enrollment(session, CONTRACT_ID, DATA)
        resp_with_allow_duplicate_cn = self.cps.create_enrollment(session, CONTRACT_ID, DATA, allowDuplicateCn=True)
        resp_with_switch_key = self.cps_with_key.create_enrollment(session, CONTRACT_ID, DATA, allowDuplicateCn=True)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments?contractId=test_contract"
        assert resp.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment.v11+json"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

        assert resp_with_allow_duplicate_cn.status_code == 200
        assert resp_with_allow_duplicate_cn.request.url == "https://www.example.com/cps/v2/enrollments?contractId" \
                                                           "=test_contract&allow-duplicate-cn=true"
        assert resp_with_allow_duplicate_cn.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment" \
                                                                               ".v11+json"
        assert resp_with_allow_duplicate_cn.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment" \
                                                                         "-status.v1+json"

        assert resp_with_switch_key.status_code == 200
        assert resp_with_switch_key.request.url == "https://www.example.com/cps/v2/enrollments?contractId" \
                                                   "=test_contract&allow-duplicate-cn=true&accountSwitchKey=key"
        assert resp_with_switch_key.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment.v11+json"
        assert resp_with_switch_key.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

    @pytest.mark.parametrize("session", [("PUT", "https://www.example.com/cps/v2/enrollments/test_enrollment", 200)],
                             indirect=True)
    def test_update_enrollment(self, session):
        resp = self.cps.update_enrollment(session, ENROLLMENT_ID, DATA)
        resp_with_switch_key = self.cps_with_key.update_enrollment(session, ENROLLMENT_ID, DATA)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment?allow-cancel-pending" \
                                   "-changes=true"
        assert resp.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment.v11+json"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

        assert resp_with_switch_key.status_code == 200
        assert resp_with_switch_key.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment?allow" \
                                                   "-cancel-pending-changes=true&accountSwitchKey=key"
        assert resp_with_switch_key.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment.v11+json"
        assert resp_with_switch_key.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/cps/v2/enrollments", 200)], indirect=True)
    def test_list_enrollments(self, session):
        resp = self.cps.list_enrollments(session, CONTRACT_ID)
        resp_with_optional = self.cps.list_enrollments(session, "optional")
        resp_with_switch_key = self.cps_with_key.list_enrollments(session, CONTRACT_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments?contractId=test_contract"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollments.v11+json"

        assert resp_with_optional.status_code == 200
        assert resp_with_optional.request.url == "https://www.example.com/cps/v2/enrollments"
        assert resp_with_optional.request.headers["Accept"] == "application/vnd.akamai.cps.enrollments.v11+json"

        assert resp_with_switch_key.status_code == 200
        assert resp_with_switch_key.request.url == "https://www.example.com/cps/v2/enrollments?contractId" \
                                                   "=test_contract&accountSwitchKey=key"
        assert resp_with_switch_key.request.headers["Accept"] == "application/vnd.akamai.cps.enrollments.v11+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/cps/v2/enrollments/test_enrollment", 200)],
                             indirect=True)
    def test_list_enrollments(self, session):
        resp = self.cps.get_enrollment(session, ENROLLMENT_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment.v11+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/cps/v2/enrollments/test_enrollment/changes"
                                                 "/test_change", 200)], indirect=True)
    def test_get_change_status(self, session):
        resp = self.cps.get_change_status(session, ENROLLMENT_ID, CHANGE_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment/changes/test_change"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.change.v1+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/cps/v2/enrollments/test_enrollment/history"
                                                 "/changes", 200)], indirect=True)
    def test_get_change_history(self, session):
        resp = self.cps.get_change_history(session, ENROLLMENT_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment/history/changes"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.change-history.v3+json"

    @pytest.mark.parametrize("session", [("DELETE", "https://www.example.com/cps/v2/enrollments/test_enrollment/changes"
                                                 "/test_change", 200)], indirect=True)
    def test_cancel_change(self, session):
        resp = self.cps.cancel_change(session, ENROLLMENT_ID, CHANGE_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment/changes/test_change"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.change-id.v1+json"

    @pytest.mark.parametrize("session", [("DELETE", "https://www.example.com/cps/v2/enrollments/test_enrollment", 200)],
                             indirect=True)
    def test_delete_enrollment(self, session):
        resp = self.cps.delete_enrollment(session, ENROLLMENT_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/cps/v2/enrollments/test_enrollment"
                                                 "/deployments/production", 200)], indirect=True)
    def test_get_certificate(self, session):
        resp = self.cps.get_certificate(session, ENROLLMENT_ID)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/cps/v2/enrollments/test_enrollment/deployments/production"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.deployment.v3+json"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/test_endpoint", 200)], indirect=True)
    def test_get_dv_change_info(self, session):
        resp = self.cps.get_dv_change_info(session, ENDPOINT)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/test_endpoint"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.dv-challenges.v2+json"

    @pytest.mark.parametrize("session", [("POST", "https://www.example.com/test_endpoint", 200)], indirect=True)
    def test_custom_post_call(self, session):
        headers = {
            "Content-Type": "application/vnd.akamai.cps.enrollment.v4+json",
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        resp = self.cps.custom_post_call(session, headers, ENDPOINT)
        resp_with_data = self.cps.custom_post_call(session, headers, ENDPOINT, DATA)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/test_endpoint"
        assert resp.request.headers["Content-Type"] == "application/vnd.akamai.cps.enrollment.v4+json"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"

        assert resp_with_data.status_code == 200
        assert resp_with_data.request.url == "https://www.example.com/test_endpoint"

    @pytest.mark.parametrize("session", [("GET", "https://www.example.com/test_endpoint", 200)], indirect=True)
    def test_custom_get_call(self, session):
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json"
        }
        resp = self.cps.custom_get_call(session, headers, ENDPOINT)

        assert resp.status_code == 200
        assert resp.request.url == "https://www.example.com/test_endpoint"
        assert resp.request.headers["Accept"] == "application/vnd.akamai.cps.enrollment-status.v1+json"
