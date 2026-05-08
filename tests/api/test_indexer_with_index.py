from concurrent import futures

import grpc
import pytest

from pyenvector.api.connection import Connection
from pyenvector.api.grpc import Indexer
from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb
from pyenvector.proto_gen.v2.endpoint import endpoint_api_pb2_grpc as envector_grpc
from pyenvector.proto_gen.v2.endpoint import endpoint_message_pb2 as envector_msg_pb2


class MockEnvectorService(envector_grpc.EndpointServiceServicer):
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

    def get_index_summary(self, request, context):
        response = envector_msg_pb2.GetIndexSummaryResponse()
        response.header.return_code = envector_type_pb.ReturnCode.Success
        index = self.indexes[request.index_name]
        response.index_summary.index_name = request.index_name
        response.index_summary.dim = index["dim"]
        response.index_summary.search_type = index["search_type"]
        response.index_summary.key_id = index["key_id"]
        response.index_summary.index_encryption = "cipher"
        response.index_summary.query_encryption = "plain"
        response.index_summary.index_type = envector_type_pb.IndexType.FLAT
        response.index_summary.is_loaded = True
        response.index_summary.is_key_loaded = True
        return response

    def clone_index(self, request, context):
        response = envector_msg_pb2.CloneIndexResponse()
        response.header.return_code = envector_type_pb.ReturnCode.Success
        source = self.indexes[request.source_index_name]
        self.indexes[request.target_index_name] = dict(source)
        response.target_index_name = request.target_index_name
        return response


@pytest.fixture(scope="module")
def grpc_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    envector_grpc.add_EndpointServiceServicer_to_server(MockEnvectorService(), server)
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


def test_get_index_summary_and_clone_index(grpc_server):
    connection = Connection(grpc_server)
    indexer = Indexer(connection)

    indexer.create_index("source_index", "key1", 64, search_type="ip")

    summary = indexer.get_index_summary("source_index")
    assert summary["index_name"] == "source_index"
    assert summary["dim"] == 64
    assert summary["key_id"] == "key1"

    cloned = indexer.clone_index("source_index", "cloned_index")
    assert cloned == {
        "source_index_name": "source_index",
        "target_index_name": "cloned_index",
    }

    index_list = indexer.get_index_list()
    assert "cloned_index" in index_list
