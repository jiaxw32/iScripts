import json
from datetime import datetime, timezone, timedelta

def convert_to_unix_timestamp(timeinterval):
    reference_date = datetime(2001, 1, 1, tzinfo=timezone.utc)
    # delta = datetime.fromtimestamp(0) - datetime.utcfromtimestamp(0)
    locat_datetime = reference_date + timedelta(seconds=timeinterval)
    # s = locat_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return datetime.timestamp(locat_datetime)

class LogManifestModel:
    species = "LogManifestModel"

    def __init__(self):
        self._filename = None
        self._filepath = None
        self._title = None
        self._identifier = None
        self._scheme = None
        self._begintime = 0
        self._endtime = 0
        self._classname = None
        self._signature = None
        self._duration = 0
        self._original_logs = None
    
    @staticmethod
    def model_with_dic(data):
        model = LogManifestModel()
        model.filename = data["fileName"]
        model.title = data["title"]
        model.identifier = data["uniqueIdentifier"]
        model.scheme = data["schemeIdentifier-schemeName"]
        starttime = data["timeStartedRecording"]
        endtime = data["timeStoppedRecording"]
        model.duration = endtime - starttime
        model.begintime = convert_to_unix_timestamp(starttime)
        model.endtime = convert_to_unix_timestamp(endtime)
        model.classname = data["className"]
        model.signature = data["signature"]
        model.original_logs = json.dumps(data)
        return model
    
    @property
    def filepath(self):
        return self._filepath
    
    @filepath.setter
    def filepath(self, value):
        self._filepath = value

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, value):
        self._filename = value
    
    @property
    def title(self):
        return self._title
    
    @title.setter
    def title(self, value):
        self._title = value

    @property
    def identifier(self):
        return self._identifier
    
    @identifier.setter
    def identifier(self, value):
        self._identifier = value

    @property
    def scheme(self):
        return self._scheme
    
    @scheme.setter
    def scheme(self, value):
        self._scheme =value

    @property
    def begintime(self):
        return self._begintime
    
    @begintime.setter
    def begintime(self, value):
        self._begintime =value
    
    @property
    def endtime(self):
        return self._endtime
    
    @endtime.setter
    def endtime(self, value):
        self._endtime =value
    
    @property
    def classname(self):
        return self._classname
    
    @classname.setter
    def classname(self, value):
        self._classname =value
    
    @property
    def signature(self):
        return self._signature
    
    @signature.setter
    def signature(self, value):
        self._signature =value
    
    @property
    def duration(self):
        return self._duration
    
    @duration.setter
    def duration(self, value):
        self._duration = value
    
    @property
    def original_logs(self):
        return self._original_logs
    
    @original_logs.setter
    def original_logs(self, value):
        self._original_logs = value
