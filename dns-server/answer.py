from dataclasses import dataclass
from time import time

@dataclass
class Answer:
    name: bytes
    type: bytes
    class_: bytes
    time_to_live: bytes
    data_length: bytes
    rdata: bytes

    def __init__(self, name, type, class_, time_to_live, data_length, rdata):
        self.name = name
        self.type = type
        self.class_ = class_
        self.time_to_live = time_to_live
        self.data_length = data_length
        self.rdata = rdata

