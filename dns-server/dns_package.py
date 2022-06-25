from dataclasses import dataclass
from time import time

from query import Query
from answer import Answer


@dataclass
class DnsPackage:
    transaction_id: bytes

    flags: bytes
    flag_q_r: bytes
    flag_opcode: bytes
    flag_authoritative: bytes
    flag_trancated: bytes
    flag_recursion_desired: bytes
    flag_recursion_available: bytes
    flag_z: bytes
    flag_answer_authenticated: bytes
    flag_non_authenticated_data: bytes
    flag_reply_code: bytes

    questions_count: bytes
    answer_rrs: bytes
    authority_rrs: bytes
    additional_rrs: bytes

    queries: list[Query]
    answer_servers: list[Answer]
    authoritative_nameservers: list[Answer]
    additional_records: list[Answer]

    package: bytes
    time_in_sec_from_epoch_start: float


    def __init__(self, transaction_id: bytes,
                 flags: bytes,
                 questions_count: bytes,
                 answer_rrs: bytes,
                 authority_rrs: bytes,
                 additional_rrs: bytes,
                 queries: list[Query],
                 answer_servers: list[Answer],
                 authoritative_nameservers: list[Answer],
                 additional_records: list[Answer],
                 package: bytes,
                 ttl: float,
                 query: str):
        self.transaction_id = transaction_id
        self.flags = flags
        self.questions_count = questions_count
        self.answer_rrs = answer_rrs
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs
        self.queries = queries
        self.answer_servers = answer_servers
        self.authoritative_nameservers = authoritative_nameservers
        self.additional_records = additional_records
        self.package = package
        self.ttl = ttl
        self.query = query
        self.time_in_sec_from_epoch_start = time()

