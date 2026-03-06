"""
Tests for Continuous Test Runner and Streaming Functionality

Tests the test runner module and SSE streaming endpoints.
"""

import pytest
import json
import time
import threading
import queue
from unittest.mock import Mock, patch, MagicMock

from llm_attack_lab.testing.test_runner import (
    ContinuousTestRunner,
    TestResult,
    TestStatus,
    TestRunSummary,
    StreamingTestPlugin,
    get_test_runner,
    stream_test_events,
)


class TestTestResult:
    """Tests for TestResult dataclass"""

    def test_create_test_result(self):
        """Test creating a test result"""
        result = TestResult(
            nodeid="test_module.py::TestClass::test_method",
            name="test_method",
            status=TestStatus.PASSED,
            duration=0.123,
            message="",
            output="test output"
        )

        assert result.nodeid == "test_module.py::TestClass::test_method"
        assert result.name == "test_method"
        assert result.status == TestStatus.PASSED
        assert result.duration == 0.123
        assert result.output == "test output"

    def test_test_result_to_dict(self):
        """Test TestResult serialization to dict"""
        result = TestResult(
            nodeid="test.py::test_func",
            name="test_func",
            status=TestStatus.FAILED,
            duration=1.5,
            message="AssertionError"
        )

        d = result.to_dict()
        assert d["nodeid"] == "test.py::test_func"
        assert d["name"] == "test_func"
        assert d["status"] == "failed"
        assert d["duration"] == 1.5
        assert d["message"] == "AssertionError"
        assert "timestamp" in d


class TestTestRunSummary:
    """Tests for TestRunSummary dataclass"""

    def test_default_summary(self):
        """Test default summary values"""
        summary = TestRunSummary()
        assert summary.total == 0
        assert summary.passed == 0
        assert summary.failed == 0
        assert summary.skipped == 0
        assert summary.errors == 0
        assert summary.duration == 0.0
        assert summary.status == "pending"

    def test_summary_to_dict(self):
        """Test summary serialization"""
        summary = TestRunSummary(
            total=10, passed=8, failed=1, skipped=1, duration=5.5, status="completed"
        )

        d = summary.to_dict()
        assert d["total"] == 10
        assert d["passed"] == 8
        assert d["failed"] == 1
        assert d["skipped"] == 1
        assert d["status"] == "completed"


class TestTestStatus:
    """Tests for TestStatus enum"""

    def test_status_values(self):
        """Test status enum values"""
        assert TestStatus.PENDING.value == "pending"
        assert TestStatus.RUNNING.value == "running"
        assert TestStatus.PASSED.value == "passed"
        assert TestStatus.FAILED.value == "failed"
        assert TestStatus.SKIPPED.value == "skipped"
        assert TestStatus.ERROR.value == "error"


class TestStreamingTestPlugin:
    """Tests for pytest streaming plugin"""

    def test_plugin_initialization(self):
        """Test plugin initializes with queue"""
        q = queue.Queue()
        plugin = StreamingTestPlugin(q)
        assert plugin.result_queue is q
        assert plugin.start_time is None

    def test_emit_event(self):
        """Test event emission to queue"""
        q = queue.Queue()
        plugin = StreamingTestPlugin(q)

        plugin._emit_event("test_event", {"key": "value"})

        event = q.get(timeout=1)
        assert event["type"] == "test_event"
        assert event["data"] == {"key": "value"}
        assert "timestamp" in event


class TestContinuousTestRunner:
    """Tests for ContinuousTestRunner"""

    def test_runner_initialization(self):
        """Test runner initializes correctly"""
        runner = ContinuousTestRunner(test_path="tests")
        assert runner.test_path == "tests"
        assert runner.is_running is False
        assert runner.current_run_id == 0
        assert len(runner.subscribers) == 0

    def test_subscribe_unsubscribe(self):
        """Test subscriber management"""
        runner = ContinuousTestRunner()

        sub_queue = runner.subscribe()
        assert len(runner.subscribers) == 1
        assert sub_queue in runner.subscribers

        runner.unsubscribe(sub_queue)
        assert len(runner.subscribers) == 0

    def test_get_status(self):
        """Test getting runner status"""
        runner = ContinuousTestRunner()
        status = runner.get_status()

        assert "is_running" in status
        assert "run_id" in status
        assert "continuous" in status
        assert "interval" in status
        assert "subscribers" in status
        assert status["is_running"] is False

    def test_start_single_run_when_not_running(self):
        """Test starting single run"""
        runner = ContinuousTestRunner()
        runner._execute_tests = Mock()

        result = runner.start_single_run()

        assert result["status"] == "started"
        assert result["run_id"] == 1
        assert runner.is_running is True

        # Wait for thread to complete
        runner.run_thread.join(timeout=2)

    def test_start_when_already_running(self):
        """Test starting when tests are already running"""
        runner = ContinuousTestRunner()
        runner.is_running = True
        runner.current_run_id = 5

        result = runner.start_single_run()

        assert result["status"] == "already_running"
        assert result["run_id"] == 5

    def test_stop(self):
        """Test stopping test run"""
        runner = ContinuousTestRunner()
        runner.is_running = True

        result = runner.stop()

        assert result["status"] == "stopping"
        assert runner.should_stop is True

    def test_broadcast_event(self):
        """Test broadcasting events to subscribers"""
        runner = ContinuousTestRunner()
        sub1 = runner.subscribe()
        sub2 = runner.subscribe()

        event = {"type": "test", "data": "hello"}
        runner._broadcast_event(event)

        assert sub1.get(timeout=1) == event
        assert sub2.get(timeout=1) == event


class TestGetTestRunner:
    """Tests for global test runner instance"""

    def test_get_test_runner_returns_instance(self):
        """Test getting global instance"""
        runner1 = get_test_runner()
        runner2 = get_test_runner()

        assert runner1 is runner2
        assert isinstance(runner1, ContinuousTestRunner)


@pytest.mark.web
class TestStreamingAPIEndpoints:
    """Tests for streaming API endpoints"""

    def test_test_status_endpoint(self, client):
        """Test /api/tests/status endpoint"""
        response = client.get('/api/tests/status')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "is_running" in data
        assert "run_id" in data

    def test_start_tests_endpoint(self, client):
        """Test /api/tests/start endpoint"""
        response = client.post(
            '/api/tests/start',
            json={"args": []},
            content_type='application/json'
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "status" in data

        # Stop if running
        client.post('/api/tests/stop')

    def test_start_continuous_tests_endpoint(self, client):
        """Test /api/tests/start-continuous endpoint"""
        response = client.post(
            '/api/tests/start-continuous',
            json={"interval": 60, "args": []},
            content_type='application/json'
        )
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "status" in data

        # Stop if running
        client.post('/api/tests/stop')

    def test_stop_tests_endpoint(self, client):
        """Test /api/tests/stop endpoint"""
        response = client.post('/api/tests/stop')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "status" in data

    def test_stream_endpoint_content_type(self, client):
        """Test /api/tests/stream returns correct content type"""
        response = client.get('/api/tests/stream')

        assert 'text/event-stream' in response.content_type
        assert response.headers.get('Cache-Control') == 'no-cache'


class TestStreamTestEvents:
    """Tests for stream_test_events generator"""

    def test_stream_events_is_generator(self):
        """Test stream_test_events returns a generator"""
        import types
        gen = stream_test_events()
        assert isinstance(gen, types.GeneratorType)
        # Clean up
        gen.close()
