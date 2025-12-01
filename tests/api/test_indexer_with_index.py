from concurrent import futures

import grpc
import pytest

from pyenvector.api.connection import Connection
from pyenvector.api.grpc import Indexer
from pyenvector.proto_gen import type_pb2 as envector_type_pb
from pyenvector.proto_gen.es2e import es2e_api_pb2_grpc as envector_grpc
from pyenvector.proto_gen.es2e import es2e_message_pb2 as envector_msg_pb2


class MockEnvectorService(envector_grpc.ES2EServiceServicer):
    def __init__(self):
        self.indexes = {}

    def create_index(self, request_iterator, context):
        # Client-streaming: consume first request only for this test
        for request in request_iterator:
            self.indexes[request.index_info.index_name] = {
                "key_id": request.index_info.key_id,
                "dim": request.index_info.dim,
                "search_type": request.index_info.search_type,
            }
            break
        response = envector_msg_pb2.CreateIndexResponse()
        response.header.return_code = envector_type_pb.ReturnCode.Success
        return response

    def get_index_list(self, request, context):
        response = envector_msg_pb2.GetIndexListResponse()
        response.header.return_code = envector_type_pb.ReturnCode.Success
        response.index_names.extend(self.indexes.keys())
        return response


@pytest.fixture(scope="module")
def grpc_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    envector_grpc.add_ES2EServiceServicer_to_server(MockEnvectorService(), server)
    port = server.add_insecure_port("[::]:50051")
    server.start()
    yield f"localhost:{port}"
    server.stop(0)


def test_create_index(grpc_server):
    connection = Connection(grpc_server)
    indexer = Indexer(connection)

    # Test create_index
    indexer.create_index("test_index", "key1", 128, search_type="ip")

    # Test get_index_list
    index_list = indexer.get_index_list()
    assert "test_index" in index_list
