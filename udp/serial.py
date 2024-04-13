import datetime
import re

ISO_DATETIME_REGEX = r"^(\d{4})-0?(\d+)-0?(\d+)[T ]0?(\d+):0?(\d+):0?(\d+).0?(\d+)$" # Based on code from https://stackoverflow.com/users/234248/mykhal from https://stackoverflow.com/q/3143070

class Encoder:
    def __call__(self, obj):
        return Encoder.datetime(obj)
    
    @staticmethod
    def datetime(obj):
        if isinstance(obj, (datetime.datetime)):
            return obj.isoformat()
        else:
            return obj
    
class Decoder:
    def __call__(self, obj):
        if "timestamp" in obj:
            return {"timestamp":Decoder.datetime(obj["timestamp"])}
        else:
            return obj
    
    @staticmethod
    def datetime(obj):
        if re.match(ISO_DATETIME_REGEX, obj):
            return datetime.datetime.fromisoformat(obj)
        else:
            return obj
        


if __name__ == "__main__":
    from pprint import pprint
    import json
    x = {"head":{"timestamp":datetime.datetime.now()},"body":"HELLO"}
    pprint(x)
    y = json.dumps(x, default=Encoder())
    pprint(y)
    z = json.loads(y, object_hook=Decoder())
    pprint(z)
    print(x==z)
    # x = r"2024-03-26T00:17:26.435120"
    # print(bool(re.match(ISO_DATETIME_REGEX, x)))
    # pprint(Decoder.datetime(x))
    
    
    