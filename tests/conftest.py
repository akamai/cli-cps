import pytest
import requests_mock
import requests


@pytest.fixture(scope="function")
def session(request):
    session = requests.Session()
    with requests_mock.Mocker(session=session) as m:
        match request.param[0]:
            case "GET":
                m.get(request.param[1], status_code=request.param[2])
            case "POST":
                m.post(request.param[1], status_code=request.param[2])
            case "PUT":
                m.put(request.param[1], status_code=request.param[2])
            case "DELETE":
                m.delete(request.param[1], status_code=request.param[2])

        yield session
