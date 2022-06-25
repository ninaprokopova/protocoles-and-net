import pickle

from dns_package import DnsPackage
class DnsCache:
    #словарь в котором по ключу хранится запрос по значению - ответ в виде DnsPackage
    cache_dict : dict[bytes, DnsPackage]

    def __init__(self):
        self.cache_dict = {}

