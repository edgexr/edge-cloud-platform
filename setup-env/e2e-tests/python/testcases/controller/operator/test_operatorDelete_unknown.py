#!/usr/local/bin/python3

#
# delete an operator with unknown name
# verify 'Key not found' error is received
# 

import unittest
import grpc
import sys
import time
from delayedassert import expect, expect_equal, assert_expectations

import mex_controller

controller_address = '127.0.0.1:55001'

operator_name = 'dummyOperator'

mex_root_cert = 'mex-ca.crt'
mex_cert = 'localserver.crt'
mex_key = 'localserver.key'

class tc(unittest.TestCase):
    def setUp(self):
        self.controller = mex_controller.Controller(controller_address = controller_address,
                                                    root_cert = mex_root_cert,
                                                    key = mex_key,
                                                    client_cert = mex_cert
                                                   )

    def test_DeleteOperatorUnknown(self):
        # print operators before add
        operator_pre = self.controller.show_operators()

        # create operator
        error = None
        self.operator = mex_controller.Operator(operator_name = operator_name)
        try:
            self.controller.delete_operator(self.operator.operator)
        except grpc.RpcError as e:
            print('got exception', e)
            error = e

        # print operators after add
        operator_post = self.controller.show_operators()
        
        expect_equal(error.code(), grpc.StatusCode.UNKNOWN, 'status code')
        expect_equal(error.details(), 'Key not found', 'error details')
        expect_equal(len(operator_post), len(operator_pre), 'num operator')

        assert_expectations()

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(tc)
    sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())

