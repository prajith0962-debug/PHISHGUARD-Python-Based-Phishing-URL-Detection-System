"""Open this file in IDLE and press F5 to run all tests."""
import unittest

import test_phishguard

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_phishguard)
    unittest.TextTestRunner(verbosity=2).run(suite)
