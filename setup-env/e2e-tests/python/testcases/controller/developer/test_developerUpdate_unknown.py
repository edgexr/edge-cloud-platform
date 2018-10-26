#!/usr/local/bin/python3

#
# update developer with unknown name
# verify 'Key not found' is received
# 

import unittest
import grpc
import sys
import time
from delayedassert import expect, expect_equal, assert_expectations
import logging

import mex_controller

controller_address = '127.0.0.1:55001'

mex_root_cert = 'mex-ca.crt'
mex_cert = 'localserver.crt'
mex_key = 'localserver.key'

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class tc(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.controller = mex_controller.Controller(controller_address = controller_address,
                                                    root_cert = mex_root_cert,
                                                    key = mex_key,
                                                    client_cert = mex_cert
                                                   )

    def test_createDeveloperEmptyName(self):
        # print developers before add
        developer_pre = self.controller.show_developers()

        # create developer
        error = None
        self.developer = mex_controller.Developer(developer_name = 'unknown developer')
        try:
            self.controller.update_developer(self.developer.developer)
        except grpc.RpcError as e:
            logging.info('got exception ' + str(e))
            error = e

        # print developers after add
        developer_post = self.controller.show_developers()
        
        expect_equal(error.code(), grpc.StatusCode.UNKNOWN, 'status code')
        expect_equal(error.details(), 'Key not found', 'error details')
        expect_equal(len(developer_post), len(developer_pre), 'num developer')

        assert_expectations()

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(tc)
    sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())

