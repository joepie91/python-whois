import unittest

from pythonwhois.ratelimit.cool_down_tracker import CoolDownTracker


class CoolDownTrackerTest(unittest.TestCase):
    """
    Test the stats of the CoolDownTracker. The tests are focused on choosing the correct cool down.
    """

    def test_decrement(self):
        tracker_1 = CoolDownTracker(2)
        tracker_1.use_and_reset_cool_down()
        self.assertEqual(tracker_1.current_cool_down, 2)

        tracker_2 = CoolDownTracker(5)
        tracker_2.use_and_reset_cool_down()
        self.assertEqual(tracker_2.current_cool_down, 5)

        tracker_1.decrement_cool_down(1)
        tracker_2.decrement_cool_down(2.5)
        self.assertEqual(tracker_1.current_cool_down, 1)
        self.assertEqual(tracker_2.current_cool_down, 2.5)

    def test_minute_limit_reached(self):
        tracker = CoolDownTracker(1, max_requests_minute=5)
        for _ in range(5):
            tracker.use_and_reset_cool_down()

        self.assertEqual(tracker.current_cool_down, 60)

    def test_hour_limit_reached(self):
        tracker = CoolDownTracker(1, max_requests_hour=10)
        for _ in range(10):
            tracker.use_and_reset_cool_down()

        self.assertEqual(tracker.current_cool_down, 3600)

    def test_day_limit_reached(self):
        tracker = CoolDownTracker(1, max_requests_day=20)
        for _ in range(20):
            tracker.use_and_reset_cool_down()

        self.assertEqual(tracker.current_cool_down, 86400)

    def test_should_use_day_limit(self):
        tracker = CoolDownTracker(1, max_requests_minute=5, max_requests_hour=13, max_requests_day=20)
        for _ in range(20):
            tracker.use_and_reset_cool_down()

        self.assertEqual(tracker.current_cool_down, 86400)
